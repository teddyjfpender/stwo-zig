//! Research-only completion of the standalone R-008 provider STARK.
//!
//! This is the first role for which all three trace trees are genuinely
//! independent: two canonical selectors, exactly 445 provider main columns,
//! and exactly eight provider interaction columns. The guest relation pair is
//! copied from the two-leaf manifest after both Tree-1 roots exist. No local
//! challenge draw can replace it.
//!
//! The resulting proof is deliberately not a production split leaf. The
//! ordered call-list commitment is not constrained by this AIR, no accepted
//! joint interaction-PoW rule exists yet, and recursion does not verify this
//! proof. Production proof meaning remains unchanged.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const core_air = @import("stwo_core").air;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const prover_air = @import("stwo_prover_engine").air;
const stage_profile = @import("stwo_prover_api").stage_profile;
const base_statement = @import("../../air/statement.zig");
const guest_interaction = @import("../../air/guest_precompile/interaction.zig");
const guest_interaction_plan = @import("../../air/guest_precompile/interaction_plan.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const logup = @import("../../air/logup.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const types = @import("../types.zig");
const split_component_assembly = @import("split_component_assembly.zig");
const split_leaf_prepare = @import("split_leaf_prepare.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const split_pcs_prepare = @import("split_pcs_prepare.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const PRODUCES_REAL_PROVIDER_STARK = true;
pub const VERIFIES_REAL_PROVIDER_STARK = true;
pub const PROVIDER_TREE2_IS_COMPLETE = true;
pub const CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const JOINT_INTERACTION_POW_IMPLEMENTED = false;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;
pub const CREATES_WORK_POOL = false;

pub const tree_count: usize = 3;
pub const provider_interaction_columns: usize =
    guest_interaction.provider_column_count;
pub const provider_batch_count: usize = guest_interaction.provider_batch_count;
pub const provider_claim_domain_words = [6]u32{
    0x5357_5453, // "STWS"
    0x3143_4950, // "PIC1"
    split_pcs_prepare.format_version,
    @intFromEnum(aggregation_types.LeafRole.poseidon2_provider),
    provider_batch_count,
    provider_interaction_columns,
};

/// A standalone provider lacks the wider base components that raise the
/// integrated composition domain. Its cubic constraints require one extra
/// quotient-domain bit beyond the provider adapter's local `log_size + 1`
/// bound. This research-only wrapper changes no row constraint or trace shape;
/// it raises only the proof's composition-domain authority.
const StandaloneProviderProver = struct {
    inner: prover_air.component_prover.ComponentProver,

    fn asComponent(self: *const @This()) prover_air.component_prover.ComponentProver {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateAtPoint,
                .evaluateConstraintQuotientsOnDomain = evaluateOnDomain,
            },
            .profile_identity = self.inner.profile_identity,
            .prepare_domain_evaluator = if (self.inner.prepare_domain_evaluator != null)
                prepareDomainEvaluator
            else
                null,
            .domain_parallel_evaluator = if (self.inner.domain_parallel_evaluator != null)
                evaluateOnDomainParallel
            else
                null,
            .pool_exclusive_domain = self.inner.pool_exclusive_domain,
        };
    }

    fn cast(ctx: *const anyopaque) *const @This() {
        return @ptrCast(@alignCast(ctx));
    }
    fn nConstraints(ctx: *const anyopaque) usize {
        return cast(ctx).inner.nConstraints();
    }
    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).inner.maxConstraintLogDegreeBound() + 1;
    }
    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!core_air.components.TraceLogDegreeBounds {
        return cast(ctx).inner.traceLogDegreeBounds(allocator);
    }
    fn maskPoints(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        point: @import("stwo_core").circle.CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_air.components.MaskPoints {
        return cast(ctx).inner.maskPoints(
            allocator,
            point,
            max_log_degree_bound,
        );
    }
    fn preprocessedColumnIndices(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return cast(ctx).inner.preprocessedColumnIndices(allocator);
    }
    fn evaluateAtPoint(
        ctx: *const anyopaque,
        point: @import("stwo_core").circle.CirclePointQM31,
        mask: *const core_air.components.MaskValues,
        accumulator: *core_air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void {
        return cast(ctx).inner.evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }
    fn evaluateOnDomain(
        ctx: *const anyopaque,
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
    ) anyerror!void {
        return cast(ctx).inner.evaluateConstraintQuotientsOnDomain(
            trace,
            accumulator,
        );
    }
    fn prepareDomainEvaluator(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
    ) anyerror!prover_air.prepared_domain.PreparedDomainEvaluation {
        const inner = cast(ctx).inner;
        const prepare = inner.prepare_domain_evaluator orelse unreachable;
        return prepare(inner.ctx, allocator, trace, accumulator);
    }
    fn evaluateOnDomainParallel(
        ctx: *const anyopaque,
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
        pool: *@import("stwo_prover_engine").work_pool.WorkPool,
    ) anyerror!void {
        const inner = cast(ctx).inner;
        const evaluate = inner.domain_parallel_evaluator orelse unreachable;
        return evaluate(inner.ctx, trace, accumulator, pool);
    }
};

const StandaloneProviderVerifier = struct {
    inner: core_air.components.Component,

    fn asComponent(self: *const @This()) core_air.components.Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateAtPoint,
            },
        };
    }

    fn cast(ctx: *const anyopaque) *const @This() {
        return @ptrCast(@alignCast(ctx));
    }
    fn nConstraints(ctx: *const anyopaque) usize {
        return cast(ctx).inner.nConstraints();
    }
    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).inner.maxConstraintLogDegreeBound() + 1;
    }
    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!core_air.components.TraceLogDegreeBounds {
        return cast(ctx).inner.traceLogDegreeBounds(allocator);
    }
    fn maskPoints(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        point: @import("stwo_core").circle.CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_air.components.MaskPoints {
        return cast(ctx).inner.maskPoints(
            allocator,
            point,
            max_log_degree_bound,
        );
    }
    fn preprocessedColumnIndices(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return cast(ctx).inner.preprocessedColumnIndices(allocator);
    }
    fn evaluateAtPoint(
        ctx: *const anyopaque,
        point: @import("stwo_core").circle.CirclePointQM31,
        mask: *const core_air.components.MaskValues,
        accumulator: *core_air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void {
        return cast(ctx).inner.evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }
};

pub const ProviderInteractionOwnerV1 = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,
    batch_sums: [provider_batch_count]QM31,
    peak_scratch_cells: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const split_pcs_prepare.ProviderRelationSourceV1,
        component: component_registry.Descriptor,
        relations: *const guest_relations.Poseidon2V1Relations,
    ) !ProviderInteractionOwnerV1 {
        try source.validate(component);
        const output_cells = try checkedMul(
            provider_interaction_columns,
            source.domain_size,
        );
        const storage = try allocator.alloc(M31, output_cells);
        errdefer allocator.free(storage);

        const scratch_rows = @min(
            guest_interaction.chunk_rows,
            @as(usize, source.n_rows),
        );
        const term_capacity = try checkedMul(provider_batch_count, scratch_rows);
        const scratch_cells = try checkedMul(term_capacity, 3);
        const scratch = try allocator.alloc(QM31, scratch_cells);
        defer allocator.free(scratch);

        var result = ProviderInteractionOwnerV1{
            .allocator = allocator,
            .storage = storage,
            .log_size = source.log_size,
            .n_rows = source.n_rows,
            .domain_size = source.domain_size,
            .batch_sums = .{QM31.zero()} ** provider_batch_count,
            .peak_scratch_cells = scratch_cells,
        };
        try result.generate(source, relations, scratch, term_capacity);
        return result;
    }

    pub fn deinit(self: *ProviderInteractionOwnerV1) void {
        if (self.storage.len != 0) self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn column(self: *const ProviderInteractionOwnerV1, index: usize) []const M31 {
        std.debug.assert(index < provider_interaction_columns);
        const start = index * self.domain_size;
        return self.storage[start..][0..self.domain_size];
    }

    fn write(
        self: *ProviderInteractionOwnerV1,
        column_index: usize,
        row: usize,
        value: M31,
    ) void {
        self.storage[column_index * self.domain_size + row] = value;
    }

    fn generate(
        self: *ProviderInteractionOwnerV1,
        source: *const split_pcs_prepare.ProviderRelationSourceV1,
        relations: *const guest_relations.Poseidon2V1Relations,
        scratch: []QM31,
        term_capacity: usize,
    ) !void {
        const numerators = scratch[0..term_capacity];
        const denominators = scratch[term_capacity..][0..term_capacity];
        const inverses = scratch[2 * term_capacity ..][0..term_capacity];
        const chunk_capacity = @min(guest_interaction.chunk_rows, self.domain_size);
        var row_destinations: [guest_interaction.chunk_rows]usize = undefined;
        var accumulators = [_]QM31{QM31.zero()} ** provider_batch_count;

        var row_start: usize = 0;
        while (row_start < self.n_rows) {
            const chunk_len = @min(chunk_capacity, self.n_rows - row_start);
            const term_len = provider_batch_count * chunk_len;
            for (0..chunk_len) |local_row| {
                const committed_row = guest_main_trace.committedRow(
                    row_start + local_row,
                    self.log_size,
                );
                row_destinations[local_row] = committed_row;
                var input: [16]M31 = undefined;
                var output: [16]M31 = undefined;
                for (&input, &output, 0..) |*input_value, *output_value, lane| {
                    input_value.* = source.column(1 + lane)[committed_row];
                    output_value.* = source.column(17 + lane)[committed_row];
                }
                const guest_term = guest_interaction_plan.providerGuestGenerationTerm(
                    source.column(0)[committed_row],
                    input,
                    output,
                    relations,
                );
                numerators[local_row] = QM31.zero();
                denominators[local_row] = QM31.one();
                guest_interaction_plan.writeNormalizedTerm(
                    logup.RowPair.single(
                        guest_term.numerator,
                        guest_term.denominator,
                    ),
                    &numerators[chunk_len + local_row],
                    &denominators[chunk_len + local_row],
                );
            }
            fields.batchInverseInPlace(
                QM31,
                denominators[0..term_len],
                inverses[0..term_len],
            ) catch return error.ZeroDenominator;
            self.writeChunk(
                chunk_len,
                &row_destinations,
                numerators,
                inverses,
                &accumulators,
            );
            row_start += chunk_len;
        }

        while (row_start < self.domain_size) {
            const chunk_len = @min(chunk_capacity, self.domain_size - row_start);
            for (0..chunk_len) |local_row| {
                row_destinations[local_row] = guest_main_trace.committedRow(
                    row_start + local_row,
                    self.log_size,
                );
            }
            for (0..provider_batch_count) |batch| {
                const coordinates = accumulators[batch].toM31Array();
                for (0..chunk_len) |local_row| {
                    for (coordinates, 0..) |coordinate, coordinate_index| {
                        self.write(
                            4 * batch + coordinate_index,
                            row_destinations[local_row],
                            coordinate,
                        );
                    }
                }
            }
            row_start += chunk_len;
        }
        self.batch_sums = accumulators;
    }

    fn writeChunk(
        self: *ProviderInteractionOwnerV1,
        chunk_len: usize,
        row_destinations: *const [guest_interaction.chunk_rows]usize,
        numerators: []const QM31,
        inverses: []const QM31,
        accumulators: *[provider_batch_count]QM31,
    ) void {
        for (0..provider_batch_count) |batch| {
            for (0..chunk_len) |local_row| {
                const index = batch * chunk_len + local_row;
                accumulators[batch] = accumulators[batch].add(
                    numerators[index].mul(inverses[index]),
                );
                for (accumulators[batch].toM31Array(), 0..) |coordinate, coordinate_index| {
                    self.write(
                        4 * batch + coordinate_index,
                        row_destinations[local_row],
                        coordinate,
                    );
                }
            }
        }
    }

    fn commit(
        self: *ProviderInteractionOwnerV1,
        comptime Engine: type,
        scheme: *Engine.Scheme,
        channel: *Engine.Channel,
        recorder: ?*stage_profile.Recorder,
    ) !void {
        if (self.storage.len == 0)
            return error.ProviderInteractionStorageAlreadyTransferred;
        const columns = try self.allocator.alloc(
            ColumnEvaluation,
            provider_interaction_columns,
        );
        errdefer self.allocator.free(columns);
        const backings = try self.allocator.alloc([]M31, 1);
        errdefer self.allocator.free(backings);
        for (columns, 0..) |*column_value, index| {
            column_value.* = .{
                .log_size = self.log_size,
                .values = @constCast(self.column(index)),
            };
        }
        backings[0] = self.storage;
        self.storage = &.{};
        try Engine.commitWithBacking(
            scheme,
            self.allocator,
            columns,
            backings,
            recorder,
            channel,
        );
    }
};

pub fn PreparedProviderTree2V1(comptime Engine: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        scheme: Engine.Scheme,
        channel: Engine.Channel,
        pcs_config: pcs_core.PcsConfig,
        construction: component_registry.ProviderConstruction,
        relations: guest_relations.Poseidon2V1Relations,
        claim: provider_component.Claim,
        roots: [tree_count]aggregation_hash.Digest,
        descriptor: aggregation_types.LeafDescriptorV1,
        session_binding: split_pcs_prepare.SharedChallengeBindingV1,
        tree2_cells: usize,
        tree2_peak_scratch_cells: usize,

        pub fn deinit(self: *Self) void {
            Engine.deinit(&self.scheme, self.allocator);
            self.* = undefined;
        }

        pub fn validate(self: *Self) !void {
            try self.claim.validate(self.construction);
            try validateBindingRelation(self.session_binding, &self.relations);
            const actual_roots = try readProviderRoots(
                Engine,
                self.allocator,
                &self.scheme,
            );
            if (!std.meta.eql(actual_roots, self.roots) or
                !aggregation_hash.eql(self.roots[0], self.descriptor.preprocessed_root) or
                !aggregation_hash.eql(self.roots[1], self.descriptor.main_root) or
                self.tree2_cells == 0)
            {
                return error.InvalidPreparedProviderTree2;
            }
        }

        /// Consume the retained three-tree PCS state and produce one genuine
        /// provider STARK. The output still is not an accepted split leaf: its
        /// public call commitment is not AIR-bound and recursion is absent.
        pub fn prove(
            self: *Self,
            recorder: ?*stage_profile.Recorder,
        ) !types.ProofForEngine(Engine) {
            var self_owned = true;
            defer if (self_owned) self.deinit();
            try self.validate();
            var assembly: split_component_assembly.ProviderProverAssembly = undefined;
            try assembly.initInto(
                self.construction,
                &self.relations,
                self.claim,
            );
            var standalone = StandaloneProviderProver{
                .inner = assembly.active()[0],
            };
            const components = [_]prover_air.component_prover.ComponentProver{
                standalone.asComponent(),
            };

            const allocator = self.allocator;
            const scheme = self.scheme;
            var channel = self.channel;
            // Component handles borrow `self.relations` through the complete
            // engine call. The scheme is consumed by `Engine.prove`, while a
            // deferred disarm prevents this owner from retaining a duplicate.
            self_owned = false;
            defer self.* = undefined;
            var extended = try Engine.prove(
                allocator,
                &components,
                &channel,
                scheme,
                .{ .recorder = recorder },
            );
            const proof = extended.proof;
            extended.aux.deinit(allocator);
            return proof;
        }
    };
}

/// Consumes `prepared` on every return. A cancellation or failure destroys the
/// complete private scheme, so no two-tree or partially committed three-tree
/// state can escape.
pub fn finishProviderTree2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    session: *const aggregation_manifest.PreparedSessionV1,
    prepared: *split_pcs_prepare.PreparedProviderPcsV1(Engine),
    cancellation: ?*const split_pcs_prepare.CancellationTokenV1,
    recorder: ?*stage_profile.Recorder,
) !PreparedProviderTree2V1(Engine) {
    var prepared_owned = true;
    defer if (prepared_owned) prepared.deinit();
    try checkCancellation(cancellation);
    try extension.validate(core);
    try prepared.validate();
    if (prepared.phase != .session_bound)
        return error.ProviderSessionNotBound;
    const binding = prepared.session_binding orelse
        return error.ProviderSessionNotBound;
    if (!aggregation_hash.eql(binding.session_digest, session.session_digest) or
        !aggregation_hash.eql(
            binding.challenge_context_digest,
            session.challenge.challenge_context_digest,
        ) or
        !std.meta.eql(binding.guest_z, session.challenge.z) or
        !std.meta.eql(binding.guest_alpha, session.challenge.alpha))
    {
        return error.ProviderSessionBindingMismatch;
    }
    const authority = try split_component_assembly.resolveProviderAuthority(
        session,
        1,
    );
    if (!std.meta.eql(authority.leaf.descriptor, prepared.descriptor) or
        !std.meta.eql(authority.construction.descriptor, prepared.authority.component))
    {
        return error.ProviderSessionDescriptorMismatch;
    }
    const relations = try split_component_assembly.bindSessionGuestRelation(
        session,
        guest_relations.Poseidon2V1Relations.dummy(),
    );
    var interaction = try ProviderInteractionOwnerV1.init(
        allocator,
        &prepared.relation_source,
        authority.construction.descriptor,
        &relations,
    );
    defer interaction.deinit();
    const claim = try provider_component.Claim.canonical(
        authority.construction,
        interaction.batch_sums,
    );

    try checkCancellation(cancellation);
    var channel = prepared.channel;
    try mixProviderInteractionClaim(&channel, authority.construction, claim);
    try interaction.commit(
        Engine,
        &prepared.scheme,
        &channel,
        recorder,
    );
    try Engine.flushPendingCommit(&prepared.scheme, allocator, &channel);
    try checkCancellation(cancellation);
    const roots = try readProviderRoots(Engine, allocator, &prepared.scheme);
    if (!aggregation_hash.eql(roots[0], prepared.roots[0]) or
        !aggregation_hash.eql(roots[1], prepared.roots[1]))
    {
        return error.ProviderCommitmentPrefixChanged;
    }

    const result = PreparedProviderTree2V1(Engine){
        .allocator = allocator,
        .scheme = prepared.scheme,
        .channel = channel,
        .pcs_config = prepared.pcs_config,
        .construction = authority.construction,
        .relations = relations,
        .claim = claim,
        .roots = roots,
        .descriptor = prepared.descriptor,
        .session_binding = binding,
        .tree2_cells = try checkedMul(
            provider_interaction_columns,
            prepared.relation_source.domain_size,
        ),
        .tree2_peak_scratch_cells = interaction.peak_scratch_cells,
    };
    prepared.relation_source.deinit();
    prepared.* = undefined;
    prepared_owned = false;
    return result;
}

/// Independent verifier replay for the research provider STARK. `proof_in` is
/// consumed on success and failure. Successful verification proves the
/// provider AIR and transcript above, but not the descriptor's call-list hash.
pub fn verifyProviderStarkV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    session: *const aggregation_manifest.PreparedSessionV1,
    identities: *const split_leaf_statement.VerifierOwnedLeafIdentitiesV1,
    proof_in: types.ProofForEngine(Engine),
    claim: provider_component.Claim,
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    try extension.validate(core);
    const authority = try split_component_assembly.resolveProviderAuthority(session, 1);
    try claim.validate(authority.construction);
    const leaf_statement = try split_leaf_statement.ProviderLeafStatementV1.init(
        session,
        1,
        identities,
    );
    try leaf_statement.validateAgainstSession(session, identities);
    try verifyProviderPreprocessedRootV1(
        Engine,
        allocator,
        pcs_config,
        authority.construction.descriptor,
        authority.leaf.descriptor.preprocessed_root,
    );
    const profile_statement_digest = try extension.digest(core);
    const expected_declaration = try split_pcs_prepare.preSessionDeclarationDigest(
        .poseidon2_provider,
        authority.leaf.descriptor,
        authority.construction.descriptor,
        profile_statement_digest,
    );
    if (!aggregation_hash.eql(
        expected_declaration,
        authority.leaf.descriptor.leaf_statement_digest,
    )) return error.ProviderDeclarationMismatch;
    if (proof.commitment_scheme_proof.commitments.items.len != 4)
        return core_verifier.VerificationError.InvalidStructure;
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (!aggregation_hash.eql(commitments[0], authority.leaf.descriptor.preprocessed_root) or
        !aggregation_hash.eql(commitments[1], authority.leaf.descriptor.main_root))
    {
        return error.ProviderCommitmentRootMismatch;
    }

    const accepted = aggregation_types.AcceptedProtocolV1{
        .proof_protocol_digest = identities.protocol.proof_protocol_digest,
        .relation_registry_digest = identities.protocol.relation_registry_digest,
    };
    const prepare_authority = split_leaf_prepare.ProviderPrepareAuthorityV1{
        .accepted_protocol = accepted,
        .job_digest = authority.leaf.descriptor.job_digest,
        .air_artifact_digest = identities.artifact.air_artifact_digest,
        .component = identities.artifact.component,
    };
    const call_count = std.math.cast(
        u32,
        authority.leaf.descriptor.guest_call_count,
    ) orelse return error.CallCountOutOfRange;
    try prepare_authority.validate(call_count);

    var channel = Engine.Channel{};
    split_pcs_prepare.mixPreTreePrefixV1(
        .poseidon2_provider,
        pcs_config,
        &channel,
        core,
        prepare_authority,
        profile_statement_digest,
        authority.leaf.descriptor.guest_call_commitment,
        authority.leaf.descriptor.guest_call_count,
    );
    var commitment_scheme = try pcs_verifier.CommitmentSchemeVerifier(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer commitment_scheme.deinit(allocator);
    const log_size = authority.construction.descriptor.log_size;
    try commitment_scheme.commit(
        allocator,
        commitments[0],
        &[_]u32{ log_size, log_size },
        &channel,
    );
    const main_logs = [_]u32{log_size} ** 445;
    try commitment_scheme.commit(
        allocator,
        commitments[1],
        &main_logs,
        &channel,
    );
    _ = try split_pcs_prepare.mixPostBarrierBindingV1(
        .poseidon2_provider,
        &channel,
        session,
        identities,
    );
    const relations = try split_component_assembly.bindSessionGuestRelation(
        session,
        guest_relations.Poseidon2V1Relations.dummy(),
    );
    try mixProviderInteractionClaim(&channel, authority.construction, claim);
    try commitment_scheme.commit(
        allocator,
        commitments[2],
        &[_]u32{log_size} ** provider_interaction_columns,
        &channel,
    );

    var assembly: split_component_assembly.ProviderVerifierAssembly = undefined;
    try assembly.initInto(authority.construction, &relations, claim);
    var standalone = StandaloneProviderVerifier{
        .inner = assembly.active()[0],
    };
    const components = [_]core_air.components.Component{
        standalone.asComponent(),
    };
    proof_moved = true;
    try core_verifier.verify(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
        allocator,
        &components,
        &channel,
        &commitment_scheme,
        proof,
    );
}

const provider_verification = @import("split_provider_verification.zig");
pub const verifyProviderPreprocessedRootV1 =
    provider_verification.verifyProviderPreprocessedRootV1;
pub const mixProviderInteractionClaim =
    provider_verification.mixProviderInteractionClaim;

fn validateBindingRelation(
    binding: split_pcs_prepare.SharedChallengeBindingV1,
    relations: *const guest_relations.Poseidon2V1Relations,
) !void {
    try binding.guest_z.validate();
    try binding.guest_alpha.validate();
    const expected = @TypeOf(relations.guest_poseidon2_io).init(
        secureFromWire(binding.guest_z),
        secureFromWire(binding.guest_alpha),
    );
    if (!relations.guest_poseidon2_io.z.eql(expected.z) or
        !relations.guest_poseidon2_io.alpha.eql(expected.alpha))
    {
        return error.ProviderSessionBindingMismatch;
    }
    for (relations.guest_poseidon2_io.alpha_powers, expected.alpha_powers) |actual, wanted| {
        if (!actual.eql(wanted))
            return error.ProviderSessionBindingMismatch;
    }
}

fn secureFromWire(value: aggregation_types.SecureFelt) QM31 {
    return QM31.fromU32Unchecked(
        value.limbs[0],
        value.limbs[1],
        value.limbs[2],
        value.limbs[3],
    );
}

fn readProviderRoots(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    scheme: *Engine.Scheme,
) ![tree_count]aggregation_hash.Digest {
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != tree_count)
        return error.InvalidProviderTreeCount;
    return .{ roots.items[0], roots.items[1], roots.items[2] };
}

fn checkCancellation(
    cancellation: ?*const split_pcs_prepare.CancellationTokenV1,
) !void {
    if (cancellation) |token| {
        if (token.isRequested())
            return error.SplitProviderFinishCancelled;
    }
}

fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch
        return error.SplitProviderResourceOverflow;
}

comptime {
    if (provider_batch_count != 2 or provider_interaction_columns != 8 or
        split_pcs_prepare.provider_relation_source_columns != 33)
    {
        @compileError("R-008 provider finish geometry drifted");
    }
}
