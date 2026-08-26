//! Research-only completion of the R-008 base-plus-caller STARK.
//!
//! The caller retains the production Tree-1 epoch as the only authority for
//! base opcode, clock, and lookup-counter inputs. After the manifest-bound
//! guest relation exists, this module draws only the twelve caller-local base
//! relations, executes the unchanged production Tree-2 kernel, appends exactly
//! 308 caller interaction columns, and proves the unchanged base components
//! plus the existing caller component.
//!
//! This is deliberately not a production split leaf. The ordered call-list
//! commitment is not constrained by either AIR, no joint interaction-PoW rule
//! has been accepted, and recursion does not yet verify the pair.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const core_verifier = @import("stwo_core").verifier;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const base_statement = @import("../../air/statement.zig");
const public_logup = @import("../../air/public_logup.zig");
const relation_challenges = @import("../../air/relation_challenges.zig");
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_interaction = @import("../../air/guest_precompile/interaction.zig");
const guest_interaction_plan = @import("../../air/guest_precompile/interaction_plan.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const guest_proof_admission = @import("../../air/guest_precompile/proof_admission.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const guest_transcript = @import("../../air/guest_precompile/proof_transcript.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const commitment_witness = @import("../commitment_witness.zig");
const interaction_production = @import("../interaction_trace_plan_execution_production.zig");
const opcode_trace = @import("../opcode_trace.zig");
const preprocessed = @import("../preprocessed.zig");
const base_finalize = @import("../proof_finalize.zig");
const proof_workspace = @import("../proof_workspace.zig");
const production = @import("../main_trace_plan_execution_production.zig");
const statement_geometry = @import("../statement_geometry.zig");
const tree2_main_source = @import("../tree2_main_source.zig");
const types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const split_component_assembly = @import("split_component_assembly.zig");
const split_leaf_prepare = @import("split_leaf_prepare.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const split_pcs_prepare = @import("split_pcs_prepare.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const PRODUCES_REAL_CALLER_STARK = true;
pub const VERIFIES_REAL_CALLER_STARK = true;
pub const CALLER_TREE2_IS_COMPLETE = true;
pub const CALL_COMMITMENT_IS_AIR_PROVED = false;
pub const JOINT_INTERACTION_POW_IMPLEMENTED = false;
pub const RECURSIVE_VERIFICATION_IMPLEMENTED = false;
pub const CREATES_WORK_POOL = false;
pub const LOCAL_BASE_RELATION_COUNT = relation_challenges.RELATION_COUNT;
pub const LOCAL_GUEST_RELATION_DRAWS = 0;

pub const tree_count: usize = 3;
pub const caller_interaction_columns: usize =
    guest_interaction.caller_column_count;
pub const caller_batch_count: usize = guest_interaction.caller_batch_count;

/// Mixed after the session envelope and before the caller-local base draw.
/// The shared guest relation has already been derived by the manifest and is
/// copied into the resulting relation bundle without another draw.
pub const caller_base_relation_domain_words = [6]u32{
    0x5357_5453, // "STWS"
    0x3152_4243, // "CBR1"
    split_pcs_prepare.format_version,
    @intFromEnum(aggregation_types.LeafRole.core_request),
    relation_challenges.RELATION_COUNT,
    LOCAL_GUEST_RELATION_DRAWS,
};

/// Exact Tree-2 claim frame. The canonical base aggregate is followed by all
/// base physical claims in statement order and all 77 caller batch claims.
pub const caller_claim_domain_words = [7]u32{
    0x5357_5453,
    0x3143_4943, // "CIC1"
    split_pcs_prepare.format_version,
    @intFromEnum(aggregation_types.LeafRole.core_request),
    caller_batch_count,
    caller_interaction_columns,
    0, // no leaf-local interaction PoW in this research protocol
};

pub const CallerTree2OwnershipV1 = struct {
    base_columns: usize,
    caller_columns: usize,
    base_cells: usize,
    caller_cells: usize,
    caller_peak_scratch_cells: usize,
    caller_owner_allocations: usize,
    nested_work_pools: usize,
};

/// Exact caller-only LogUp owner. It is intentionally separate from the
/// combined generator: the latter remains the production differential oracle.
pub const CallerInteractionOwnerV1 = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    log_size: u32,
    n_rows: u32,
    domain_size: usize,
    batch_sums: [caller_batch_count]QM31,
    peak_scratch_cells: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        source: *const split_pcs_prepare.CallerRelationSourceV1,
        component: component_registry.Descriptor,
        relations: *const guest_relations.Poseidon2V1Relations,
    ) !CallerInteractionOwnerV1 {
        try source.validate(component);
        const output_cells = try checkedMul(
            caller_interaction_columns,
            source.domain_size,
        );
        const storage = try allocator.alloc(M31, output_cells);
        errdefer allocator.free(storage);

        const scratch_rows = @min(
            guest_interaction.chunk_rows,
            @as(usize, source.n_rows),
        );
        const term_capacity = try checkedMul(caller_batch_count, scratch_rows);
        const scratch_cells = try checkedMul(term_capacity, 3);
        var scratch: []QM31 = &[_]QM31{};
        if (scratch_cells != 0) scratch = try allocator.alloc(QM31, scratch_cells);
        defer if (scratch.len != 0) allocator.free(scratch);

        var result = CallerInteractionOwnerV1{
            .allocator = allocator,
            .storage = storage,
            .log_size = source.log_size,
            .n_rows = source.n_rows,
            .domain_size = source.domain_size,
            .batch_sums = .{QM31.zero()} ** caller_batch_count,
            .peak_scratch_cells = scratch_cells,
        };
        try result.generate(source, relations, scratch, term_capacity);
        return result;
    }

    pub fn deinit(self: *CallerInteractionOwnerV1) void {
        if (self.storage.len != 0) self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn column(self: *const CallerInteractionOwnerV1, index: usize) []const M31 {
        std.debug.assert(index < caller_interaction_columns);
        const start = index * self.domain_size;
        return self.storage[start..][0..self.domain_size];
    }

    fn write(
        self: *CallerInteractionOwnerV1,
        column_index: usize,
        row: usize,
        value: M31,
    ) void {
        self.storage[column_index * self.domain_size + row] = value;
    }

    fn generate(
        self: *CallerInteractionOwnerV1,
        source: *const split_pcs_prepare.CallerRelationSourceV1,
        relations: *const guest_relations.Poseidon2V1Relations,
        scratch: []QM31,
        term_capacity: usize,
    ) !void {
        const numerators = scratch[0..term_capacity];
        const denominators = scratch[term_capacity..][0..term_capacity];
        const inverses = scratch[2 * term_capacity ..][0..term_capacity];
        const chunk_capacity = @min(guest_interaction.chunk_rows, self.domain_size);
        var row_destinations: [guest_interaction.chunk_rows]usize = undefined;
        var accumulators = [_]QM31{QM31.zero()} ** caller_batch_count;

        var row_start: usize = 0;
        while (row_start < self.n_rows) {
            const chunk_len = @min(chunk_capacity, self.n_rows - row_start);
            const term_len = caller_batch_count * chunk_len;
            for (0..chunk_len) |local_row| {
                const committed_row = guest_main_trace.committedRow(
                    row_start + local_row,
                    self.log_size,
                );
                row_destinations[local_row] = committed_row;
                var main: [split_pcs_prepare.caller_relation_source_columns]M31 =
                    undefined;
                for (&main, 0..) |*value, column_index| {
                    value.* = source.column(column_index)[committed_row];
                }
                guest_interaction_plan.writeCallerGenerationTerms(
                    &main,
                    relations,
                    numerators,
                    denominators,
                    chunk_len,
                    local_row,
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
            for (0..caller_batch_count) |batch| {
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
        self: *CallerInteractionOwnerV1,
        chunk_len: usize,
        row_destinations: *const [guest_interaction.chunk_rows]usize,
        numerators: []const QM31,
        inverses: []const QM31,
        accumulators: *[caller_batch_count]QM31,
    ) void {
        for (0..caller_batch_count) |batch| {
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
};

pub fn CallerProofOutputV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        proof: types.ProofForEngine(Engine),
        base_claim: *base_statement.RiscVInteractionClaim,
        caller_claim: caller_component.Claim,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            self.proof.deinit(self.allocator);
            self.allocator.destroy(self.base_claim);
            self.* = undefined;
        }

        pub fn deinitAfterProofMoved(self: *Self) void {
            self.allocator.destroy(self.base_claim);
            self.* = undefined;
        }
    };
}

pub fn PreparedCallerTree2V1(comptime Engine: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        scheme: Engine.Scheme,
        channel: Engine.Channel,
        pcs_config: pcs_core.PcsConfig,
        statement: *const base_statement.RiscVStatement,
        construction: component_registry.CallerConstruction,
        relations: guest_relations.Poseidon2V1Relations,
        base_claim: *base_statement.RiscVInteractionClaim,
        caller_claim: caller_component.Claim,
        roots: [tree_count]aggregation_hash.Digest,
        descriptor: aggregation_types.LeafDescriptorV1,
        session_binding: split_pcs_prepare.SharedChallengeBindingV1,
        composition_execution: prover_api.CpuCompositionExecutionRequest,
        ownership: CallerTree2OwnershipV1,

        pub fn deinit(self: *Self) void {
            Engine.deinit(&self.scheme, self.allocator);
            self.allocator.destroy(self.base_claim);
            self.* = undefined;
        }

        pub fn validate(self: *Self) !void {
            try self.caller_claim.validate(self.construction);
            try validateBindingRelation(
                self.session_binding,
                &self.relations,
            );
            const expected_base_cells = try countLogCellsFromClaim(
                self.statement,
                self.base_claim,
            );
            if (self.construction.descriptor.log_size >= @bitSizeOf(usize))
                return error.InvalidPreparedCallerTree2;
            const caller_domain = @as(usize, 1) <<
                @intCast(self.construction.descriptor.log_size);
            const expected_caller_cells = try checkedMul(
                caller_interaction_columns,
                caller_domain,
            );
            const expected_caller_scratch = try checkedMul(
                try checkedMul(
                    caller_batch_count,
                    @min(
                        guest_interaction.chunk_rows,
                        @as(usize, self.construction.descriptor.n_rows),
                    ),
                ),
                3,
            );
            const expected_caller_allocations: usize =
                1 + @as(usize, @intFromBool(expected_caller_scratch != 0));
            if (self.base_claim.interaction_pow != 0 or
                self.base_claim.n_components != self.statement.n_components or
                self.base_claim.n_infra != self.statement.n_infra or
                self.ownership.caller_columns != caller_interaction_columns or
                self.ownership.base_columns != self.statement.nInteractionColumns() or
                self.ownership.base_cells != expected_base_cells or
                self.ownership.caller_cells != expected_caller_cells or
                self.ownership.caller_peak_scratch_cells != expected_caller_scratch or
                self.ownership.caller_owner_allocations != expected_caller_allocations or
                self.ownership.nested_work_pools != 0)
            {
                return error.InvalidPreparedCallerTree2;
            }
            _ = try self.base_claim.canonical(self.statement);
            try verifyCallerLocalClosure(
                self.statement,
                self.construction,
                &self.relations,
                self.base_claim,
                self.caller_claim,
            );
            const actual_roots = try readCallerRoots(
                Engine,
                self.allocator,
                &self.scheme,
            );
            if (!std.meta.eql(actual_roots, self.roots) or
                !aggregation_hash.eql(self.roots[0], self.descriptor.preprocessed_root) or
                !aggregation_hash.eql(self.roots[1], self.descriptor.main_root))
            {
                return error.InvalidPreparedCallerTree2;
            }
        }

        /// Consume the complete three-tree caller state. `workspace` remains
        /// caller-owned and must be the exact workspace whose statement was
        /// authenticated by the retained production Tree-1 epoch.
        pub fn prove(
            self: *Self,
            workspace: *proof_workspace.ProofWorkspace,
            recorder: ?*stage_profile.Recorder,
        ) !CallerProofOutputV1(Engine) {
            var self_owned = true;
            defer if (self_owned) self.deinit();
            try self.validate();
            if (&workspace.statement != self.statement)
                return error.CallerWorkspaceStatementAuthorityMismatch;

            // Every component stores relation pointers. Keep one stack-stable
            // copy alive through `Engine.prove`; the PCS owner itself is
            // disarmed before that consuming call and may be overwritten.
            const relations = self.relations;
            const base_components = try base_finalize.assemble(
                workspace,
                &relations.base,
                self.base_claim,
                self.statement.nMainColumns(),
                self.statement.nInteractionColumns(),
            );
            var assembly: split_component_assembly.CallerProverAssembly = undefined;
            try assembly.initInto(
                self.statement,
                self.construction,
                &relations,
                base_components,
                self.caller_claim,
            );

            const allocator = self.allocator;
            const scheme = self.scheme;
            var channel = self.channel;
            const base_claim = self.base_claim;
            const caller_claim = self.caller_claim;
            const composition_execution = self.composition_execution;
            self_owned = false;
            self.* = undefined;
            var claim_owned = true;
            errdefer if (claim_owned) allocator.destroy(base_claim);
            var extended = try Engine.prove(
                allocator,
                assembly.active(),
                &channel,
                scheme,
                .{
                    .recorder = recorder,
                    .cpu_composition_execution = composition_execution,
                },
            );
            const proof = extended.proof;
            extended.aux.deinit(allocator);
            claim_owned = false;
            return .{
                .allocator = allocator,
                .proof = proof,
                .base_claim = base_claim,
                .caller_claim = caller_claim,
            };
        }
    };
}

/// Consumes both `prepared` and `base_prepared` on every return. The execution
/// pool is borrowed; this function never creates or nests one.
pub fn finishCallerTree2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    workspace: *proof_workspace.ProofWorkspace,
    extension: *const guest_statement.ExtensionStatement,
    witness: *const commitment_witness.CommitmentWitness,
    geometry: statement_geometry.Geometry,
    session: *const aggregation_manifest.PreparedSessionV1,
    prepared: *split_pcs_prepare.PreparedCallerPcsV1(Engine),
    base_prepared: *production.Prepared,
    execution_request: prover_api.CpuCompositionExecutionRequest,
    pool: ?*work_pool.WorkPool,
    cancellation: ?*const split_pcs_prepare.CancellationTokenV1,
    recorder: ?*stage_profile.Recorder,
) !PreparedCallerTree2V1(Engine) {
    var prepared_owned = true;
    defer if (prepared_owned) prepared.deinit();
    defer base_prepared.deinit();
    try checkCancellation(cancellation);

    const core = &workspace.statement;
    try extension.validate(core);
    try prepared.validate();
    if (prepared.phase != .session_bound)
        return error.CallerSessionNotBound;
    const binding = prepared.session_binding orelse
        return error.CallerSessionNotBound;
    try validateBinding(session, binding);
    const retained_statement = try base_prepared.retainedStatement();
    if (retained_statement != core or prepared.descriptor.role != .core_request)
        return error.CallerBaseStatementAuthorityMismatch;

    const authority = try split_component_assembly.resolveCallerAuthority(
        session,
        0,
    );
    if (!std.meta.eql(authority.leaf.descriptor, prepared.descriptor) or
        !std.meta.eql(authority.construction.descriptor, prepared.authority.component))
    {
        return error.CallerSessionDescriptorMismatch;
    }

    const base_claim = try allocator.create(base_statement.RiscVInteractionClaim);
    var base_claim_owned = true;
    errdefer if (base_claim_owned) allocator.destroy(base_claim);
    base_claim.initZeroInto();
    base_claim.n_components = core.n_components;
    base_claim.n_infra = core.n_infra;
    base_claim.interaction_pow = 0;

    var channel = prepared.channel;
    const relations = try drawCallerRelationsV1(allocator, &channel, session);
    const main_source = tree2_main_source.Source.fromPlanned(base_prepared);
    const ordinary_steps = std.math.sub(
        u32,
        core.total_steps,
        extension.counts.n_guest,
    ) catch return error.CallerExecutionCountMismatch;
    if (try base_prepared.retainedOrdinarySteps() != ordinary_steps)
        return error.CallerExecutionCountMismatch;
    var base_tree2 = try interaction_production.Prepared.prepareWithOrdinarySteps(
        allocator,
        core,
        ordinary_steps,
        .{
            .witness = witness,
            .geometry = geometry,
            .main_source = main_source,
            .relations = &relations.base,
            .claim = base_claim,
        },
        execution_request,
        if (pool) |active_pool| active_pool.workerCount() else 1,
        if (pool) |active_pool|
            active_pool.stackSize()
        else
            work_pool.WORKER_STACK_SIZE,
    );
    defer base_tree2.deinit();
    _ = try base_tree2.execute(pool);
    try checkCancellation(cancellation);

    var caller_interaction = try CallerInteractionOwnerV1.init(
        allocator,
        &prepared.relation_source,
        authority.construction.descriptor,
        &relations,
    );
    defer caller_interaction.deinit();
    const caller_claim = try caller_component.Claim.canonical(
        authority.construction,
        caller_interaction.batch_sums,
    );
    try verifyCallerLocalClosure(
        core,
        authority.construction,
        &relations,
        base_claim,
        caller_claim,
    );

    try checkCancellation(cancellation);
    try mixCallerInteractionClaimV1(
        &channel,
        core,
        base_claim,
        authority.construction,
        caller_claim,
    );
    const base_column_count: usize = base_tree2.plan().total_columns;
    const base_cells = try countLogCellsFromClaim(core, base_claim);
    try commitMergedCallerTree2(
        Engine,
        allocator,
        &prepared.scheme,
        &channel,
        recorder,
        &base_tree2,
        &caller_interaction,
    );
    try Engine.flushPendingCommit(&prepared.scheme, allocator, &channel);
    try checkCancellation(cancellation);
    const roots = try readCallerRoots(Engine, allocator, &prepared.scheme);
    if (!aggregation_hash.eql(roots[0], prepared.roots[0]) or
        !aggregation_hash.eql(roots[1], prepared.roots[1]))
    {
        return error.CallerCommitmentPrefixChanged;
    }

    const result = PreparedCallerTree2V1(Engine){
        .allocator = allocator,
        .scheme = prepared.scheme,
        .channel = channel,
        .pcs_config = prepared.pcs_config,
        .statement = core,
        .construction = authority.construction,
        .relations = relations,
        .base_claim = base_claim,
        .caller_claim = caller_claim,
        .roots = roots,
        .descriptor = prepared.descriptor,
        .session_binding = binding,
        .composition_execution = execution_request,
        .ownership = .{
            .base_columns = base_column_count,
            .caller_columns = caller_interaction_columns,
            .base_cells = base_cells,
            .caller_cells = try checkedMul(
                caller_interaction_columns,
                prepared.relation_source.domain_size,
            ),
            .caller_peak_scratch_cells = caller_interaction.peak_scratch_cells,
            .caller_owner_allocations = 1 + @as(usize, @intFromBool(
                caller_interaction.peak_scratch_cells != 0,
            )),
            .nested_work_pools = 0,
        },
    };
    base_claim_owned = false;
    prepared.relation_source.deinit();
    prepared.* = undefined;
    prepared_owned = false;
    return result;
}

/// Independent verifier replay for the research caller STARK. `proof_in` is
/// consumed on success and failure. The call-list digest remains native and is
/// therefore not promoted to a verified split-leaf output here.
pub fn verifyCallerStarkV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    session: *const aggregation_manifest.PreparedSessionV1,
    identities: *const split_leaf_statement.VerifierOwnedLeafIdentitiesV1,
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const base_statement.RiscVInteractionClaim,
    caller_claim: caller_component.Claim,
) !void {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    _ = try guest_proof_admission.canonical(core, extension, .proof);
    try extension.validate(core);
    const authority = try split_component_assembly.resolveCallerAuthority(
        session,
        0,
    );
    try caller_claim.validate(authority.construction);
    const leaf_statement = try split_leaf_statement.CallerLeafStatementV1.init(
        session,
        0,
        identities,
    );
    try leaf_statement.validateAgainstSession(session, identities);
    try verifyCallerPreprocessedRootV1(
        Engine,
        allocator,
        pcs_config,
        core,
        authority.construction.descriptor,
        authority.leaf.descriptor.preprocessed_root,
    );

    const profile_statement_digest = try extension.digest(core);
    const expected_declaration = try split_pcs_prepare.preSessionDeclarationDigest(
        .core_request,
        authority.leaf.descriptor,
        authority.construction.descriptor,
        profile_statement_digest,
    );
    if (!aggregation_hash.eql(
        expected_declaration,
        authority.leaf.descriptor.leaf_statement_digest,
    )) return error.CallerDeclarationMismatch;
    if (proof.commitment_scheme_proof.commitments.items.len != 4)
        return core_verifier.VerificationError.InvalidStructure;
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (!aggregation_hash.eql(commitments[0], authority.leaf.descriptor.preprocessed_root) or
        !aggregation_hash.eql(commitments[1], authority.leaf.descriptor.main_root))
    {
        return error.CallerCommitmentRootMismatch;
    }

    const accepted = aggregation_types.AcceptedProtocolV1{
        .proof_protocol_digest = identities.protocol.proof_protocol_digest,
        .relation_registry_digest = identities.protocol.relation_registry_digest,
    };
    const prepare_authority = split_leaf_prepare.CallerPrepareAuthorityV1{
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
        .core_request,
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

    const tree0_logs = try callerTree0LogSizes(
        allocator,
        core,
        authority.construction.descriptor,
    );
    defer allocator.free(tree0_logs);
    try commitment_scheme.commit(
        allocator,
        commitments[0],
        tree0_logs,
        &channel,
    );
    const tree1_logs = try callerTree1LogSizes(
        allocator,
        core,
        authority.construction.descriptor,
    );
    defer allocator.free(tree1_logs);
    try commitment_scheme.commit(
        allocator,
        commitments[1],
        tree1_logs,
        &channel,
    );
    _ = try split_pcs_prepare.mixPostBarrierBindingV1(
        .core_request,
        &channel,
        session,
        identities,
    );
    const relations = try drawCallerRelationsV1(allocator, &channel, session);
    try verifyCallerLocalClosure(
        core,
        authority.construction,
        &relations,
        base_claim,
        caller_claim,
    );
    try mixCallerInteractionClaimV1(
        &channel,
        core,
        base_claim,
        authority.construction,
        caller_claim,
    );
    const tree2_logs = try callerTree2LogSizes(
        allocator,
        core,
        base_claim,
        authority.construction.descriptor,
    );
    defer allocator.free(tree2_logs);
    try commitment_scheme.commit(
        allocator,
        commitments[2],
        tree2_logs,
        &channel,
    );

    const workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    try workspace.canonicalize(base_claim, core);
    const base_components = try base_verifier.assembleComponents(
        workspace,
        core,
        base_claim,
        &relations.base,
        core.nMainColumns(),
        core.nInteractionColumns(),
    );
    var assembly: split_component_assembly.CallerVerifierAssembly = undefined;
    try assembly.initInto(
        core,
        authority.construction,
        &relations,
        base_components,
        caller_claim,
    );
    proof_moved = true;
    try core_verifier.verify(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
        allocator,
        assembly.active(),
        &channel,
        &commitment_scheme,
        proof,
    );
}

const caller_support = @import("split_caller_finish_support.zig");
pub const drawCallerRelationsV1 = caller_support.drawCallerRelationsV1;
pub const mixCallerInteractionClaimV1 = caller_support.mixCallerInteractionClaimV1;
pub const verifyCallerPreprocessedRootV1 = caller_support.verifyCallerPreprocessedRootV1;
const commitMergedCallerTree2 = caller_support.commitMergedCallerTree2;
const verifyCallerLocalClosure = caller_support.verifyCallerLocalClosure;
const callerTree0LogSizes = caller_support.callerTree0LogSizes;
const callerTree1LogSizes = caller_support.callerTree1LogSizes;
const callerTree2LogSizes = caller_support.callerTree2LogSizes;
const countLogCellsFromClaim = caller_support.countLogCellsFromClaim;
const validateBinding = caller_support.validateBinding;
const validateBindingRelation = caller_support.validateBindingRelation;
const readCallerRoots = caller_support.readCallerRoots;
const checkCancellation = caller_support.checkCancellation;
const checkedMul = caller_support.checkedMul;

comptime {
    if (caller_batch_count != 77 or caller_interaction_columns != 308 or
        split_pcs_prepare.caller_relation_source_columns != 158 or
        relation_challenges.RELATION_COUNT != 12)
    {
        @compileError("R-008 caller Tree-2 geometry drifted");
    }
}
