//! Cairo proving orchestration over the resident Metal arena.

const std = @import("std");
const arena_plan = @import("../../backends/metal/arena_plan.zig");
const schedule_bindings = @import("schedule_bindings.zig");
const metal_runtime = @import("../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../backends/metal/protocol_recipes.zig");
const transcript_fixture = @import("../../backends/metal/cairo/diagnostics/transcript_fixture.zig");
const composition_bundle_mod = @import("../../frontends/cairo/witness/composition_bundle.zig");
const fixed_table_bundle_mod = @import("../../frontends/cairo/witness/fixed_table_bundle.zig");
const relation_bundle_mod = @import("../../frontends/cairo/witness/relation_bundle.zig");
const witness_bundle_mod = @import("../../frontends/cairo/witness/bundle.zig");
const eval_codegen = @import("eval_codegen.zig");
const cairo_proof_plan = @import("../../frontends/cairo/proof_plan.zig");
const commitment_ordering = @import("resident/commitment/ordering.zig");
const commitment_telemetry = @import("resident/commitment/telemetry.zig");
const composition_config = @import("resident/composition/config.zig");
const fixed_tables = @import("resident/lookups/fixed_tables.zig");
const multiplicity_feeds = @import("resident/lookups/multiplicity_feeds.zig");
const preprocessed_bindings = @import("resident/preprocessed/bindings.zig");
const preprocessed_coefficients_mod = @import("resident/preprocessed/coefficients.zig");
const preprocessed_storage = @import("resident/preprocessed/storage.zig");
const relation_claims = @import("resident/relations/claims.zig");
const relation_components = @import("resident/relations/components.zig");
const interaction_diagnostics = @import("resident/interaction/diagnostics.zig");
const interaction_execute = @import("resident/interaction/execute.zig");
const resident_binding = @import("resident/binding.zig");
const resident_errors = @import("resident/errors.zig");
const trace_diagnostics = @import("resident/trace/diagnostics.zig");
const trace_interpolation = @import("resident/trace/interpolation.zig");
const transcript_operations = @import("resident/transcript/operations.zig");
const resident_twiddles = @import("resident/twiddles.zig");
const witness_execute = @import("resident/witness/execute.zig");
const witness_inputs = @import("resident/witness/inputs.zig");
const witness_prepare = @import("resident/witness/prepare.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const circle_poly_mod = @import("stwo_prover_impl").poly.circle.poly;
const canonic_circle_mod = @import("stwo_core").poly.circle.canonic;
const CairoMerkleHasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;

const cairo_domain_prefix_bytes = CairoMerkleHasher.domainPrefixBytes();

pub const Error = resident_errors.Error;

pub const Sn2Counts = schedule_bindings.Sn2Counts;
pub const WitnessRecipeRequirements = witness_prepare.WitnessRecipeRequirements;
pub const WitnessRecipes = witness_prepare.WitnessRecipes;

pub const ProofCopy = struct {
    source: arena_plan.Binding,
    destination_word_offset: u32,
    word_count: u32,
};

pub const CommitmentTelemetry = struct {
    gpu_ms: f64,
    lde_gpu_ms: f64,
    leaf_gpu_ms: f64,
    parent_gpu_ms: f64,
    root: arena_plan.Binding,
    command_epoch_stats: ?metal_runtime.CommandEpochStats = null,
};

pub const OrdinalBinding = schedule_bindings.OrdinalBinding;
pub const NamedBinding = schedule_bindings.NamedBinding;

pub const DecommitTraceCoefficientBindings = schedule_bindings.DecommitTraceCoefficientBindings;
pub const DecommitTraceGroupBindings = schedule_bindings.DecommitTraceGroupBindings;
pub const DecommitTraceTreeBindings = schedule_bindings.DecommitTraceTreeBindings;
pub const DecommitFriTreeBindings = schedule_bindings.DecommitFriTreeBindings;
pub const TraceTreeRole = schedule_bindings.TraceTreeRole;
pub const TraceTreeGeometry = schedule_bindings.TraceTreeGeometry;
pub const FriTreeGeometry = schedule_bindings.FriTreeGeometry;
pub const ProofDecommitGeometry = schedule_bindings.ProofDecommitGeometry;

const collectDecommitBindings = schedule_bindings.collectDecommitBindings;
const collectSn2DecommitBindings = schedule_bindings.collectSn2DecommitBindings;
const friStartLog = schedule_bindings.friStartLog;

const NamedGroupRange = schedule_bindings.NamedGroupRange;
const purpose = schedule_bindings.purpose;
const logicalId = schedule_bindings.logicalId;
const ordinal = schedule_bindings.ordinal;
const componentName = schedule_bindings.componentName;
const one = schedule_bindings.one;
const oneOrdinal = schedule_bindings.oneOrdinal;
const oneComponent = schedule_bindings.oneComponent;
const oneComponentOrdinal = schedule_bindings.oneComponentOrdinal;
const collect = schedule_bindings.collect;
const collectOrdinals = schedule_bindings.collectOrdinals;
const collectScheduleOrder = schedule_bindings.collectScheduleOrder;
const collectComponent = schedule_bindings.collectComponent;
const collectComponentBindingGroups = schedule_bindings.collectComponentBindingGroups;
const collectNamed = schedule_bindings.collectNamed;
const namedGroupRanges = schedule_bindings.namedGroupRanges;

const canonicalClaimedSumBindings = relation_claims.canonicalClaimedSumBindings;
const collectPreprocessedBindings = preprocessed_bindings.collect;
const canonicalTraceTree = commitment_ordering.canonicalTraceTree;
const collectCommitmentOrder = commitment_ordering.collectCommitmentOrder;
const collectTreePurpose = commitment_ordering.collectTreePurpose;
const commitmentOrderCopy = commitment_ordering.commitmentOrderCopy;
const reorderTraceQueryValues = commitment_ordering.reorderTraceQueryValues;

/// Exact logical-to-physical binding set consumed by the prepared composition,
/// quotient, FRI and compact proof-assembly stages. This is deliberately built
/// from the captured schedule and the colored plan; no allocation id or offset
/// is inferred from insertion order.
pub const PreparedProofBindings = struct {
    allocator: std.mem.Allocator,
    composition_coefficients: []arena_plan.Binding,
    composition_descriptors: arena_plan.Binding,
    composition_lde_tile: arena_plan.Binding,
    composition_accumulators: arena_plan.Binding,
    composition_random_powers: arena_plan.Binding,
    preprocessed_coefficients: []arena_plan.Binding,
    /// Degree-sorted column order consumed by tree-1 commitment/decommitment.
    base_coefficients: []arena_plan.Binding,
    /// Degree-sorted column order consumed by tree-2 commitment/decommitment.
    interaction_coefficients: []arena_plan.Binding,
    /// Global AIR trace-span order consumed by composition, OODS, and quotient masks.
    canonical_base_coefficients: []arena_plan.Binding,
    /// Global AIR trace-span order consumed by composition, OODS, and quotient masks.
    canonical_interaction_coefficients: []arena_plan.Binding,
    named_base_coefficients: []NamedBinding,
    named_interaction_coefficients: []NamedBinding,
    composition_ext_params: []arena_plan.Binding,
    relation_claimed_sums: []arena_plan.Binding,
    canonical_claimed_sums: []arena_plan.Binding,
    relation_alpha_powers: arena_plan.Binding,
    relation_z: arena_plan.Binding,
    relation_scan_scratch: arena_plan.Binding,
    quotient_tile: arena_plan.Binding,
    quotient_partials: []arena_plan.Binding,
    quotient_sample_points: arena_plan.Binding,
    quotient_first_linear_terms: arena_plan.Binding,
    quotient_subdomain_values: arena_plan.Binding,
    quotient_denominator_scratch: arena_plan.Binding,
    quotient_inverse_twiddles: arena_plan.Binding,
    forward_twiddles: arena_plan.Binding,
    inverse_twiddles: arena_plan.Binding,
    fri_ping: arena_plan.Binding,
    fri_pong: arena_plan.Binding,
    fri_challenges: []arena_plan.Binding,
    fri_retained_evaluations: []arena_plan.Binding,
    fri_merkle_layers: []arena_plan.Binding,
    fri_final_coefficients: arena_plan.Binding,
    fri_final_degree_error: arena_plan.Binding,
    transcript_state: arena_plan.Binding,
    transcript_inputs: []OrdinalBinding,
    transcript_outputs: []OrdinalBinding,
    decommit_raw_queries: arena_plan.Binding,
    decommit_unique_queries: arena_plan.Binding,
    decommit_mapped_queries: arena_plan.Binding,
    decommit_walk_queries: arena_plan.Binding,
    decommit_walk_scratch: arena_plan.Binding,
    decommit_expanded_positions: arena_plan.Binding,
    decommit_sparse_indices: arena_plan.Binding,
    decommit_sparse_hashes: arena_plan.Binding,
    decommit_counts: arena_plan.Binding,
    decommit_values: arena_plan.Binding,
    decommit_assembly: arena_plan.Binding,
    decommit_trace_lde_tile: arena_plan.Binding,
    decommit_trace_groups: []DecommitTraceGroupBindings,
    decommit_trace_trees: []DecommitTraceTreeBindings,
    decommit_fri_trees: []DecommitFriTreeBindings,
    proof_bytes: arena_plan.Binding,
    proof_copies: []ProofCopy,
    assembly: []arena_plan.Binding,

    pub fn initSn2(
        allocator: std.mem.Allocator,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        composition_bundle: composition_bundle_mod.Bundle,
        relation_bundle: relation_bundle_mod.Bundle,
    ) !PreparedProofBindings {
        return initInternal(allocator, schedule, plan, composition_bundle, relation_bundle, null);
    }

    /// Binds the schedule to authenticated runtime proof geometry. The caller
    /// must supply the exact tree metadata committed by its proof bundle.
    pub fn init(
        allocator: std.mem.Allocator,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        composition_bundle: composition_bundle_mod.Bundle,
        relation_bundle: relation_bundle_mod.Bundle,
        geometry: ProofDecommitGeometry,
    ) !PreparedProofBindings {
        try geometry.validate();
        return initInternal(allocator, schedule, plan, composition_bundle, relation_bundle, geometry);
    }

    fn initInternal(
        allocator: std.mem.Allocator,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        composition_bundle: composition_bundle_mod.Bundle,
        relation_bundle: relation_bundle_mod.Bundle,
        geometry: ?ProofDecommitGeometry,
    ) !PreparedProofBindings {
        const composition_coefficients = try collect(allocator, schedule, plan, "CompositionCoefficients");
        errdefer allocator.free(composition_coefficients);
        const quotient_partials = try collect(allocator, schedule, plan, "QuotientPartialNumerator");
        errdefer allocator.free(quotient_partials);
        const fri_challenges = try collect(allocator, schedule, plan, "FriFoldingChallenge");
        errdefer allocator.free(fri_challenges);
        const fri_retained_evaluations = try collect(allocator, schedule, plan, "FriRetainedEvaluation");
        errdefer allocator.free(fri_retained_evaluations);
        const fri_merkle_layers = try collect(allocator, schedule, plan, "FriMerkleLayer");
        errdefer allocator.free(fri_merkle_layers);
        const assembly = try collectAssembly(allocator, schedule, plan);
        errdefer allocator.free(assembly);
        const proof_copies = try buildProofCopies(
            allocator,
            schedule,
            plan,
            if (geometry) |runtime_geometry|
                runtime_geometry.fri_trees.len
            else
                Sn2Counts.decommit_fri_trees,
        );
        errdefer allocator.free(proof_copies);
        const transcript_inputs = try collectOrdinals(allocator, schedule, plan, "TranscriptInput");
        errdefer allocator.free(transcript_inputs);
        const transcript_outputs = try collectOrdinals(allocator, schedule, plan, "TranscriptOutput");
        errdefer allocator.free(transcript_outputs);
        var decommit_raw_queries: ?arena_plan.Binding = null;
        for (transcript_outputs) |output| {
            if (output.ordinal == 5) decommit_raw_queries = output.binding;
        }
        const preprocessed_coefficients = try collectCommitmentOrder(allocator, schedule, plan, "PreprocessedCoefficients");
        errdefer allocator.free(preprocessed_coefficients);
        const named_base_coefficients = try collectNamed(allocator, schedule, plan, "BaseCoefficients");
        errdefer allocator.free(named_base_coefficients);
        const named_interaction_coefficients = try collectNamed(allocator, schedule, plan, "InteractionCoefficients");
        errdefer allocator.free(named_interaction_coefficients);
        const canonical_base_coefficients = try canonicalTraceTree(
            allocator,
            composition_bundle,
            named_base_coefficients,
            1,
        );
        errdefer allocator.free(canonical_base_coefficients);
        const base_coefficients = try commitmentOrderCopy(allocator, canonical_base_coefficients);
        errdefer allocator.free(base_coefficients);
        const canonical_interaction_coefficients = try canonicalTraceTree(
            allocator,
            composition_bundle,
            named_interaction_coefficients,
            2,
        );
        errdefer allocator.free(canonical_interaction_coefficients);
        const interaction_coefficients = try commitmentOrderCopy(allocator, canonical_interaction_coefficients);
        errdefer allocator.free(interaction_coefficients);
        const composition_ext_params = try collect(allocator, schedule, plan, "CompositionExtParams");
        errdefer allocator.free(composition_ext_params);
        const relation_claimed_sums = try collect(allocator, schedule, plan, "RelationClaimedSum");
        errdefer allocator.free(relation_claimed_sums);
        const canonical_claimed_sums = try canonicalClaimedSumBindings(
            allocator,
            composition_bundle,
            relation_bundle,
            relation_claimed_sums,
        );
        errdefer allocator.free(canonical_claimed_sums);
        var decommit_bindings = if (geometry) |runtime_geometry|
            try collectDecommitBindings(allocator, schedule, plan, runtime_geometry)
        else
            try collectSn2DecommitBindings(allocator, schedule, plan);
        errdefer decommit_bindings.deinit(allocator);
        var result = PreparedProofBindings{
            .allocator = allocator,
            .composition_coefficients = composition_coefficients,
            .composition_descriptors = try one(schedule, plan, "CompositionDescriptors"),
            .composition_lde_tile = try one(schedule, plan, "CompositionLdeTile"),
            .composition_accumulators = try one(schedule, plan, "CompositionAccumulators"),
            .composition_random_powers = try one(schedule, plan, "CompositionRandomCoefficientPowers"),
            .preprocessed_coefficients = preprocessed_coefficients,
            .base_coefficients = base_coefficients,
            .interaction_coefficients = interaction_coefficients,
            .canonical_base_coefficients = canonical_base_coefficients,
            .canonical_interaction_coefficients = canonical_interaction_coefficients,
            .named_base_coefficients = named_base_coefficients,
            .named_interaction_coefficients = named_interaction_coefficients,
            .composition_ext_params = composition_ext_params,
            .relation_claimed_sums = relation_claimed_sums,
            .canonical_claimed_sums = canonical_claimed_sums,
            .relation_alpha_powers = try one(schedule, plan, "RelationAlphaPowers"),
            .relation_z = try one(schedule, plan, "RelationZ"),
            .relation_scan_scratch = try one(schedule, plan, "RelationScanEvalScratch"),
            .quotient_tile = try one(schedule, plan, "QuotientTile"),
            .quotient_partials = quotient_partials,
            .quotient_sample_points = try one(schedule, plan, "QuotientSamplePoints"),
            .quotient_first_linear_terms = try one(schedule, plan, "QuotientFirstLinearTerms"),
            .quotient_subdomain_values = try one(schedule, plan, "QuotientSubdomainValues"),
            .quotient_denominator_scratch = try one(schedule, plan, "QuotientDenominatorScratch"),
            .quotient_inverse_twiddles = try one(schedule, plan, "QuotientInverseTwiddles"),
            .forward_twiddles = try one(schedule, plan, "ForwardTwiddles"),
            .inverse_twiddles = try one(schedule, plan, "InverseTwiddles"),
            .fri_ping = try one(schedule, plan, "FriPing"),
            .fri_pong = try one(schedule, plan, "FriPong"),
            .fri_challenges = fri_challenges,
            .fri_retained_evaluations = fri_retained_evaluations,
            .fri_merkle_layers = fri_merkle_layers,
            .fri_final_coefficients = try one(schedule, plan, "FriFinalCoefficients"),
            .fri_final_degree_error = try one(schedule, plan, "FriFinalDegreeError"),
            .transcript_state = try one(schedule, plan, "TranscriptState"),
            .transcript_inputs = transcript_inputs,
            .transcript_outputs = transcript_outputs,
            .decommit_raw_queries = decommit_raw_queries orelse return Error.MissingBinding,
            .decommit_unique_queries = try one(schedule, plan, "DecommitUniqueQueries"),
            .decommit_mapped_queries = try one(schedule, plan, "DecommitMappedQueries"),
            .decommit_walk_queries = try one(schedule, plan, "DecommitWalkQueries"),
            .decommit_walk_scratch = try one(schedule, plan, "DecommitWalkScratch"),
            .decommit_expanded_positions = try one(schedule, plan, "DecommitExpandedPositions"),
            .decommit_sparse_indices = try one(schedule, plan, "DecommitSparseIndices"),
            .decommit_sparse_hashes = try one(schedule, plan, "DecommitSparseHashes"),
            .decommit_counts = try one(schedule, plan, "DecommitCounts"),
            .decommit_values = try one(schedule, plan, "DecommitValues"),
            .decommit_assembly = try one(schedule, plan, "DecommitAssembly"),
            .decommit_trace_lde_tile = try one(schedule, plan, "DecommitTraceLdeTile"),
            .decommit_trace_groups = decommit_bindings.trace_groups,
            .decommit_trace_trees = decommit_bindings.trace_trees,
            .decommit_fri_trees = decommit_bindings.fri_trees,
            .proof_bytes = try one(schedule, plan, "ProofBytes"),
            .proof_copies = proof_copies,
            .assembly = assembly,
        };
        if (geometry) |runtime_geometry|
            try result.validate(runtime_geometry)
        else
            try result.validateSn2();
        return result;
    }

    pub fn deinit(self: *PreparedProofBindings) void {
        self.allocator.free(self.composition_coefficients);
        self.allocator.free(self.quotient_partials);
        self.allocator.free(self.fri_challenges);
        self.allocator.free(self.fri_retained_evaluations);
        self.allocator.free(self.fri_merkle_layers);
        self.allocator.free(self.proof_copies);
        self.allocator.free(self.transcript_inputs);
        self.allocator.free(self.transcript_outputs);
        self.allocator.free(self.preprocessed_coefficients);
        self.allocator.free(self.base_coefficients);
        self.allocator.free(self.interaction_coefficients);
        self.allocator.free(self.canonical_base_coefficients);
        self.allocator.free(self.canonical_interaction_coefficients);
        self.allocator.free(self.named_base_coefficients);
        self.allocator.free(self.named_interaction_coefficients);
        self.allocator.free(self.composition_ext_params);
        self.allocator.free(self.relation_claimed_sums);
        self.allocator.free(self.canonical_claimed_sums);
        self.allocator.free(self.decommit_trace_groups);
        self.allocator.free(self.decommit_trace_trees);
        self.allocator.free(self.decommit_fri_trees);
        self.allocator.free(self.assembly);
        self.* = undefined;
    }

    pub fn prepareProofAssembly(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
    ) !protocol_recipes.ProofAssemblyRecipe {
        const copies = try allocator.alloc(protocol_recipes.ProofCopy, self.proof_copies.len);
        defer allocator.free(copies);
        for (self.proof_copies, copies) |source, *destination| {
            destination.* = .{
                .source = source.source,
                .destination_word_offset = source.destination_word_offset,
                .word_count = source.word_count,
            };
        }
        return protocol_recipes.ProofAssemblyRecipe.init(
            allocator,
            metal,
            resident_arena,
            copies,
            self.proof_bytes,
        );
    }

    pub fn prepareQuotient(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
    ) !protocol_recipes.QuotientRecipe {
        return protocol_recipes.QuotientRecipe.init(
            allocator,
            metal,
            resident_arena,
            self.quotient_partials,
            self.quotient_sample_points,
            self.quotient_first_linear_terms,
            self.quotient_denominator_scratch,
            self.quotient_subdomain_values,
            self.quotient_tile,
            self.quotient_inverse_twiddles,
            self.forward_twiddles,
        );
    }

    pub fn prepareFri(
        self: PreparedProofBindings,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        leaf_seed: [8]u32,
        node_seed: [8]u32,
    ) !protocol_recipes.FriRecipe {
        return protocol_recipes.FriRecipe.initWithGeometry(
            metal,
            resident_arena,
            try self.runtimeFriGeometry(),
            self.quotient_tile,
            self.fri_retained_evaluations,
            self.fri_challenges,
            self.inverse_twiddles,
            self.fri_ping,
            self.fri_final_coefficients,
            self.fri_final_degree_error,
            self.fri_merkle_layers,
            leaf_seed,
            node_seed,
        );
    }

    pub fn prepareTranscript(
        self: PreparedProofBindings,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
    ) !protocol_recipes.TranscriptRecipe {
        return transcript_operations.prepare(self.transcriptBindings(), metal, resident_arena);
    }

    pub fn prepareDecommitQueries(
        self: PreparedProofBindings,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
    ) !protocol_recipes.DecommitQueryRecipe {
        const tree_count = std.math.add(usize, self.decommit_trace_trees.len, self.decommit_fri_trees.len) catch
            return Error.InvalidCardinality;
        return protocol_recipes.DecommitQueryRecipe.initWithGeometry(
            metal,
            resident_arena,
            self.decommit_raw_queries,
            self.decommit_unique_queries,
            self.decommit_mapped_queries,
            self.decommit_expanded_positions,
            self.decommit_walk_queries,
            self.decommit_walk_scratch,
            self.decommit_sparse_indices,
            self.decommit_sparse_hashes,
            self.decommit_counts,
            self.decommit_assembly,
            std.math.cast(u32, tree_count) orelse return Error.InvalidCardinality,
            try self.runtimeFriGeometry(),
        );
    }

    pub fn decommitTraceTree(self: PreparedProofBindings, tree_index: u32) !DecommitTraceTreeBindings {
        if (tree_index >= self.decommit_trace_trees.len) return Error.InvalidCardinality;
        const tree = self.decommit_trace_trees[tree_index];
        if (tree.tree_index != tree_index or @intFromEnum(tree.role) != tree_index)
            return Error.InvalidSchedule;
        return tree;
    }

    pub fn decommitFriTree(self: PreparedProofBindings, round: u32) !DecommitFriTreeBindings {
        if (round >= self.decommit_fri_trees.len) return Error.InvalidCardinality;
        const tree = self.decommit_fri_trees[round];
        const tree_index = std.math.add(usize, self.decommit_trace_trees.len, round) catch
            return Error.InvalidCardinality;
        if (tree.round != round or tree.tree_index != tree_index or tree.role != tree_index)
            return Error.InvalidSchedule;
        return tree;
    }

    /// Executes the canonical SN2 trace and FRI opening schedule after query
    /// positions have been drawn. Trace LDEs stream one 16-column group at a
    /// time through the shared tile while sparse leaf hashes retain their
    /// Blake2s state across groups.
    pub fn executeSn2Decommit(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        recipe: *protocol_recipes.DecommitQueryRecipe,
        leaf_seed: [8]u32,
        node_seed: [8]u32,
    ) !f64 {
        if (self.decommit_trace_trees.len != Sn2Counts.decommit_trace_trees or
            self.decommit_fri_trees.len != Sn2Counts.decommit_fri_trees)
            return Error.InvalidCardinality;
        return self.executeDecommit(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            recipe,
            leaf_seed,
            node_seed,
        );
    }

    /// Executes trace and FRI openings in authenticated runtime tree order.
    pub fn executeDecommit(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        recipe: *protocol_recipes.DecommitQueryRecipe,
        leaf_seed: [8]u32,
        node_seed: [8]u32,
    ) !f64 {
        var lde_gpu_ms: f64 = 0;
        try recipe.normalize();
        for (0..self.decommit_trace_trees.len) |tree_index| {
            const tree = try self.decommitTraceTree(@intCast(tree_index));
            const coefficients: []const arena_plan.Binding = switch (tree.role) {
                .preprocessed => self.preprocessed_coefficients,
                .base => self.base_coefficients,
                .interaction => self.interaction_coefficients,
                .composition => self.composition_coefficients,
            };
            const canonical_coefficients: []const arena_plan.Binding = switch (tree.role) {
                .preprocessed => self.preprocessed_coefficients,
                .base => self.canonical_base_coefficients,
                .interaction => self.canonical_interaction_coefficients,
                .composition => self.composition_coefficients,
            };
            if (coefficients.len != tree.column_count) return Error.InvalidCardinality;
            const retained = try collectTreePurpose(
                allocator,
                schedule,
                plan,
                "RetainedMerkleLayers",
                tree.tree_index,
            );
            defer allocator.free(retained);
            try populateTraceRetainedPointers(resident_arena, tree, retained);
            try populateSparseOffsets(resident_arena, self.decommit_sparse_indices, tree.sparse_offsets, tree.unretained);
            try recipe.prepareTrace(tree.source_log, tree.tree_log, tree.leaf_log, tree.unretained);

            const max_leaf_count = std.math.cast(u32, 70 * (@as(u64, 1) << @intCast(tree.unretained))) orelse
                return Error.InvalidBindingSize;
            var column_cursor: usize = 0;
            for (tree.groups) |group| {
                if (group.tree_index != tree.tree_index or group.group_index * 16 != column_cursor)
                    return Error.InvalidSchedule;
                const end = std.math.add(usize, column_cursor, group.column_count) catch return Error.InvalidCardinality;
                if (end > coefficients.len) return Error.InvalidCardinality;
                const group_coefficients = coefficients[column_cursor..end];
                lde_gpu_ms += try executeDecommitTraceLdeGroup(
                    metal,
                    resident_arena,
                    self.forward_twiddles,
                    self.decommit_trace_lde_tile,
                    group,
                    group_coefficients,
                );
                try recipe.gatherTraceValues(
                    group.evaluation_pointers,
                    group.evaluation_logs,
                    group.column_count,
                    tree.tree_log,
                    @intCast(column_cursor),
                    70,
                    self.decommit_values,
                );
                try recipe.sparseLeafGroup(
                    group.evaluation_pointers,
                    group.evaluation_logs,
                    group.column_count,
                    @intCast(column_cursor),
                    tree.column_count,
                    tree.leaf_log,
                    max_leaf_count,
                    leaf_seed,
                );
                column_cursor = end;
            }
            if (column_cursor != coefficients.len) return Error.InvalidCardinality;

            var child_offset: u32 = 0;
            var child_capacity = max_leaf_count;
            for (1..tree.unretained) |distance| {
                const parent_offset = std.math.add(u32, child_offset, child_capacity) catch return Error.InvalidBindingSize;
                try recipe.sparseParent(
                    @intCast(distance),
                    child_offset,
                    child_capacity,
                    parent_offset,
                    node_seed,
                );
                child_offset = parent_offset;
                child_capacity >>= 1;
            }
            try reorderTraceQueryValues(
                allocator,
                resident_arena,
                self.decommit_values,
                coefficients,
                canonical_coefficients,
                70,
            );
            try recipe.assembleTrace(
                tree.tree_index,
                @intFromEnum(tree.role),
                tree.leaf_log,
                tree.unretained,
                tree.column_count,
                tree.retained_pointers,
                tree.sparse_offsets,
                self.decommit_values,
            );
        }

        if (self.fri_retained_evaluations.len + 1 != self.decommit_fri_trees.len)
            return Error.InvalidCardinality;
        var fri_layer_cursor: usize = 0;
        for (0..self.decommit_fri_trees.len) |round| {
            const tree = try self.decommitFriTree(@intCast(round));
            const evaluation = if (round == 0) self.quotient_tile else self.fri_retained_evaluations[round - 1];
            try populateFriCoordinatePointers(resident_arena, tree, evaluation);
            const layer_count: usize = tree.leaf_log + 1;
            if (fri_layer_cursor + layer_count > self.fri_merkle_layers.len) return Error.InvalidCardinality;
            try populateFriRetainedPointers(
                resident_arena,
                tree,
                self.fri_merkle_layers[fri_layer_cursor .. fri_layer_cursor + layer_count],
            );
            fri_layer_cursor += layer_count;
            try recipe.executeFriRound(
                round,
                tree.tree_index,
                tree.leaf_log,
                tree.coordinate_pointers,
                tree.retained_pointers,
                self.decommit_values,
            );
        }
        if (fri_layer_cursor != self.fri_merkle_layers.len) return Error.InvalidCardinality;
        const assembly_bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(self.decommit_assembly));
        const assembly_words = std.mem.bytesAsSlice(u32, assembly_bytes);
        const tree_count = std.math.cast(u32, self.decommit_trace_trees.len + self.decommit_fri_trees.len) orelse
            return Error.InvalidCardinality;
        if (assembly_words.len < 8 or assembly_words[0] != 0x4457_5453 or assembly_words[1] != 1 or
            assembly_words[2] != tree_count or assembly_words[7] == 0 or assembly_words[7] > assembly_words.len)
            return Error.InvalidBindingSize;
        return lde_gpu_ms;
    }

    pub fn prepareComposition(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        bundle: composition_bundle_mod.Bundle,
        metallib_path: []const u8,
    ) !protocol_recipes.CompositionRecipe {
        return prepareCompositionRecipe(self, allocator, metal, resident_arena, bundle, metallib_path);
    }

    pub fn prepareRelations(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        bundle: relation_bundle_mod.Bundle,
        witness_bundle: witness_bundle_mod.Bundle,
    ) !protocol_recipes.RelationRecipe {
        return relation_components.prepare(
            self.relationBindings(),
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            bundle,
            witness_bundle,
        );
    }

    /// Prepares the relation and inverse-circle FFT work as component-local
    /// operations. `executeIndex` always interpolates every interaction output
    /// before returning, so a later component may safely reuse its trace slab.
    pub fn prepareRelationComponents(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        bundle: relation_bundle_mod.Bundle,
        witness_bundle: witness_bundle_mod.Bundle,
        twiddle_storage: arena_plan.Binding,
    ) !PreparedRelationComponents {
        return relation_components.prepareComponents(
            self.relationBindings(),
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            bundle,
            witness_bundle,
            twiddle_storage,
        );
    }

    pub fn executeCommitment(
        self: PreparedProofBindings,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        tree_index: u32,
        leaf_seed: [8]u32,
        node_seed: [8]u32,
    ) !CommitmentTelemetry {
        const coefficients = switch (tree_index) {
            0 => self.preprocessed_coefficients,
            1 => self.base_coefficients,
            2 => self.interaction_coefficients,
            3 => self.composition_coefficients,
            else => return Error.InvalidCardinality,
        };
        return executeStreamingCommitment(
            self.allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            coefficients,
            self.commitmentTwiddleBinding(plan, tree_index),
            tree_index,
            leaf_seed,
            node_seed,
        );
    }

    pub fn commitmentScratchBytes(self: PreparedProofBindings, tree_index: u32) u64 {
        const coefficients = switch (tree_index) {
            0 => self.preprocessed_coefficients,
            1 => self.base_coefficients,
            2 => self.interaction_coefficients,
            3 => self.composition_coefficients,
            else => return 0,
        };
        var max_bytes: u64 = 0;
        for (coefficients) |binding| max_bytes = @max(max_bytes, binding.size_bytes);
        return max_bytes;
    }

    pub fn populateCommitmentTwiddles(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        resident_arena: *arena_plan.ResidentArena,
        plan: arena_plan.Plan,
        tree_index: u32,
    ) !void {
        try populateForwardTwiddleBinding(allocator, resident_arena, self.commitmentTwiddleBinding(plan, tree_index));
    }

    pub fn populateCommitmentInverseTwiddles(
        self: PreparedProofBindings,
        allocator: std.mem.Allocator,
        resident_arena: *arena_plan.ResidentArena,
        plan: arena_plan.Plan,
        tree_index: u32,
    ) !void {
        try populateInverseTwiddles(allocator, resident_arena, self.commitmentTwiddleBinding(plan, tree_index));
    }

    pub fn commitmentTwiddleStorage(self: PreparedProofBindings, plan: arena_plan.Plan, tree_index: u32) arena_plan.Binding {
        return self.commitmentTwiddleBinding(plan, tree_index);
    }

    pub fn restoreCommitmentRoot(
        self: PreparedProofBindings,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
        tree_index: u32,
        root: [32]u8,
    ) !void {
        _ = self;
        try transcript_operations.restoreCommitmentRoot(resident_arena, schedule, plan, tree_index, root);
    }

    pub fn materializeRelationChallenges(
        self: PreparedProofBindings,
        resident_arena: *arena_plan.ResidentArena,
    ) !void {
        try transcript_operations.materializeRelationChallenges(self.transcriptBindings(), resident_arena);
    }

    pub fn restoreRelationChallenges(
        self: PreparedProofBindings,
        resident_arena: *arena_plan.ResidentArena,
        z: [4]u32,
        alpha_words: [4]u32,
    ) !void {
        try transcript_operations.restoreRelationChallenges(self.transcriptBindings(), resident_arena, z, alpha_words);
    }

    pub fn publishInteractionClaim(
        self: PreparedProofBindings,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
    ) !void {
        try transcript_operations.publishInteractionClaim(self.transcriptBindings(), resident_arena, schedule, plan);
    }

    pub fn logRelationDiagnostics(
        self: PreparedProofBindings,
        resident_arena: *arena_plan.ResidentArena,
        relations: PreparedRelationComponents,
    ) !void {
        try relation_components.logDiagnostics(self.relationBindings(), resident_arena, relations);
    }

    fn commitmentTwiddleBinding(self: PreparedProofBindings, plan: arena_plan.Plan, tree_index: u32) arena_plan.Binding {
        _ = plan;
        _ = tree_index;
        return self.forward_twiddles;
    }

    fn relationBindings(self: PreparedProofBindings) relation_components.Bindings {
        return .{
            .claimed_sums = self.relation_claimed_sums,
            .alpha_powers = self.relation_alpha_powers,
            .z = self.relation_z,
            .scan_scratch = self.relation_scan_scratch,
        };
    }

    fn transcriptBindings(self: PreparedProofBindings) transcript_operations.Bindings {
        return .{
            .allocator = self.allocator,
            .state = self.transcript_state,
            .inputs = self.transcript_inputs,
            .outputs = self.transcript_outputs,
            .quotient_tile = self.quotient_tile,
            .relation_z = self.relation_z,
            .relation_alpha_powers = self.relation_alpha_powers,
            .canonical_claimed_sums = self.canonical_claimed_sums,
        };
    }

    fn runtimeFriGeometry(self: PreparedProofBindings) !protocol_recipes.FriGeometry {
        const geometry = protocol_recipes.FriGeometry.initRuntime(
            try friStartLog(self.quotient_tile),
            .{
                .round_count = self.decommit_fri_trees.len,
                .fold_step = protocol_recipes.FriGeometry.fold_step,
                .final_log = protocol_recipes.FriGeometry.final_log,
                .packed_log = protocol_recipes.FriGeometry.packed_log,
            },
        ) catch return Error.InvalidBindingSize;
        for (self.decommit_fri_trees, 0..) |tree, round| {
            if (tree.leaf_log != try geometry.leafLog(round)) return Error.InvalidBindingSize;
        }
        return geometry;
    }

    fn validate(self: PreparedProofBindings, geometry: ProofDecommitGeometry) !void {
        try geometry.validate();
        _ = try self.runtimeFriGeometry();
        if (self.decommit_trace_trees.len != geometry.trace_trees.len or
            self.decommit_fri_trees.len != geometry.fri_trees.len or
            self.decommit_trace_groups.len != try geometry.traceGroupCount())
            return Error.InvalidCardinality;
        if (self.fri_challenges.len != geometry.fri_trees.len) return Error.InvalidFriChallengeCount;
        if (self.fri_retained_evaluations.len + 1 != geometry.fri_trees.len)
            return Error.InvalidFriRetainedCount;
        if (self.fri_merkle_layers.len != try geometry.friLayerCount()) return Error.InvalidFriLayerCount;

        var group_cursor: usize = 0;
        for (self.decommit_trace_trees, geometry.trace_trees) |tree, expected| {
            if (tree.role != expected.role or tree.tree_index != expected.tree_index or
                tree.source_log != expected.source_log or tree.tree_log != expected.tree_log or
                tree.leaf_log != expected.leaf_log or tree.unretained != expected.unretained or
                tree.column_count != expected.column_count or tree.groups.len != expected.groupCount())
                return Error.InvalidCardinality;
            const coefficients: []const arena_plan.Binding = switch (tree.role) {
                .preprocessed => self.preprocessed_coefficients,
                .base => self.base_coefficients,
                .interaction => self.interaction_coefficients,
                .composition => self.composition_coefficients,
            };
            if (coefficients.len != tree.column_count) return Error.InvalidCardinality;
            var column_count: usize = 0;
            for (tree.groups, 0..) |group, group_index| {
                if (group_cursor >= self.decommit_trace_groups.len or
                    group.tree_index != tree.tree_index or group.group_index != group_index or
                    group.column_count == 0 or group.column_count > 16)
                    return Error.InvalidSchedule;
                column_count = std.math.add(usize, column_count, group.column_count) catch
                    return Error.InvalidCardinality;
                group_cursor += 1;
            }
            if (column_count != tree.column_count) return Error.InvalidCardinality;
        }
        if (group_cursor != self.decommit_trace_groups.len) return Error.InvalidCardinality;
        for (self.decommit_fri_trees, geometry.fri_trees) |tree, expected| {
            if (tree.role != expected.role or tree.round != expected.round or
                tree.tree_index != expected.tree_index or tree.leaf_log != expected.leaf_log)
                return Error.InvalidCardinality;
        }
        if (self.canonical_base_coefficients.len != self.base_coefficients.len or
            self.canonical_interaction_coefficients.len != self.interaction_coefficients.len)
            return Error.InvalidCardinality;
        if (self.inverse_twiddles.size_bytes == 0 or
            !std.math.isPowerOfTwo(self.inverse_twiddles.size_bytes / @sizeOf(u32)))
            return Error.InvalidBindingSize;
        try validateDisjointActiveBindings(self.inverse_twiddles, self.composition_accumulators);
        if (self.decommit_values.size_bytes == 0 or self.decommit_assembly.size_bytes == 0 or
            self.decommit_trace_lde_tile.size_bytes == 0 or self.proof_bytes.size_bytes == 0 or
            self.assembly.len == 0 or
            self.proof_copies.len != geometry.fri_trees.len + 10 or
            self.transcript_inputs.len == 0 or self.transcript_outputs.len == 0)
            return Error.InvalidBindingSize;
        var cursor: u64 = 0;
        for (self.proof_copies) |copy| {
            if (copy.destination_word_offset != cursor or copy.source.size_bytes < @as(u64, copy.word_count) * 4)
                return Error.InvalidBindingSize;
            cursor = std.math.add(u64, cursor, copy.word_count) catch return Error.InvalidBindingSize;
        }
        if (cursor * 4 != self.proof_bytes.size_bytes) return Error.InvalidBindingSize;
    }

    fn validateSn2(self: PreparedProofBindings) !void {
        if (self.composition_coefficients.len != Sn2Counts.composition_coefficients) return Error.InvalidCompositionCount;
        if (self.quotient_partials.len == 0 or self.quotient_partials.len % 4 != 0)
            return Error.InvalidQuotientCount;
        const quotient_sample_count = self.quotient_partials.len / 4;
        if (self.quotient_sample_points.size_bytes != quotient_sample_count * 8 * 4 or
            self.quotient_first_linear_terms.size_bytes != quotient_sample_count * 4 * 4)
            return Error.InvalidQuotientCount;
        for (0..quotient_sample_count) |sample| {
            const first = self.quotient_partials[sample * 4];
            if (first.size_bytes == 0 or !std.math.isPowerOfTwo(first.size_bytes / 4))
                return Error.InvalidBindingSize;
            for (self.quotient_partials[sample * 4 ..][0..4]) |partial| {
                if (partial.size_bytes != first.size_bytes) return Error.InvalidBindingSize;
            }
        }
        if (self.fri_challenges.len != Sn2Counts.fri_challenges) return Error.InvalidFriChallengeCount;
        if (self.fri_retained_evaluations.len != Sn2Counts.fri_retained_evaluations) return Error.InvalidFriRetainedCount;
        const fri_geometry = protocol_recipes.FriGeometry.init(try friStartLog(self.quotient_tile)) catch
            return Error.InvalidBindingSize;
        if (self.fri_merkle_layers.len != fri_geometry.totalLayerCount()) return Error.InvalidFriLayerCount;
        if (self.decommit_trace_groups.len != Sn2Counts.decommit_trace_groups) return Error.InvalidCardinality;
        if (self.composition_ext_params.len != 58) return Error.InvalidExtParamCount;
        if (self.relation_claimed_sums.len != 58 or self.canonical_claimed_sums.len != self.relation_claimed_sums.len)
            return Error.InvalidClaimedSumCount;
        if (self.preprocessed_coefficients.len != 161) return Error.InvalidPreprocessedCount;
        if (self.canonical_base_coefficients.len != self.base_coefficients.len or
            self.canonical_interaction_coefficients.len != self.interaction_coefficients.len)
            return Error.InvalidCardinality;
        if (self.inverse_twiddles.size_bytes == 0 or
            !std.math.isPowerOfTwo(self.inverse_twiddles.size_bytes / @sizeOf(u32)))
            return Error.InvalidBindingSize;
        try validateDisjointBindings(self.inverse_twiddles, self.composition_accumulators);
        for (self.composition_coefficients) |binding| {
            if (binding.size_bytes != self.inverse_twiddles.size_bytes) return Error.InvalidBindingSize;
        }
        if (self.fri_final_coefficients.size_bytes != 8 * 4 or
            self.fri_final_degree_error.size_bytes != 4 or
            self.transcript_state.size_bytes < 10 * 4 or self.transcript_inputs.len != 26 or self.transcript_outputs.len != 13 or
            self.decommit_values.size_bytes == 0 or
            self.decommit_assembly.size_bytes == 0 or self.decommit_trace_lde_tile.size_bytes == 0 or
            self.proof_bytes.size_bytes == 0 or self.assembly.len == 0 or
            self.proof_copies.len != 18)
            return Error.InvalidBindingSize;
        if (self.decommit_trace_trees.len != Sn2Counts.decommit_trace_trees or
            self.decommit_fri_trees.len != Sn2Counts.decommit_fri_trees)
            return Error.InvalidCardinality;
        for (self.decommit_trace_trees, Sn2Counts.decommit_trace_groups_by_tree, Sn2Counts.decommit_trace_columns_by_tree, 0..) |tree, group_count, column_count, tree_index| {
            if (tree.tree_index != tree_index or @intFromEnum(tree.role) != tree_index or
                tree.groups.len != group_count or tree.column_count != column_count)
                return Error.InvalidCardinality;
        }
        for (self.decommit_fri_trees, 0..) |tree, round| {
            if (tree.round != round or tree.tree_index != round + Sn2Counts.decommit_trace_trees or
                tree.role != tree.tree_index)
                return Error.InvalidCardinality;
        }
        var cursor: u64 = 0;
        for (self.proof_copies) |copy| {
            if (copy.destination_word_offset != cursor or copy.source.size_bytes < @as(u64, copy.word_count) * 4)
                return Error.InvalidBindingSize;
            cursor += copy.word_count;
        }
        if (cursor * 4 != self.proof_bytes.size_bytes) return Error.InvalidBindingSize;
    }
};

fn validateDisjointBindings(first: arena_plan.Binding, second: arena_plan.Binding) Error!void {
    const first_end = std.math.add(u64, first.offset_bytes, first.size_bytes) catch
        return Error.InvalidBindingSize;
    const second_end = std.math.add(u64, second.offset_bytes, second.size_bytes) catch
        return Error.InvalidBindingSize;
    if (first.offset_bytes < second_end and second.offset_bytes < first_end)
        return Error.InvalidBindingAlias;
}

fn validateDisjointActiveBindings(first: arena_plan.Binding, second: arena_plan.Binding) Error!void {
    if (!bindingHasActiveTick(first) or !bindingHasActiveTick(second)) return;
    return validateDisjointBindings(first, second);
}

fn bindingHasActiveTick(binding: arena_plan.Binding) bool {
    for (binding.occupied) |word| if (word != 0) return true;
    return false;
}

pub const RelationComponentTelemetry = relation_components.RelationComponentTelemetry;
pub const RelationComponentOperation = relation_components.RelationComponentOperation;
pub const PreparedRelationComponents = relation_components.PreparedRelationComponents;

pub const populateExecutionTables = preprocessed_coefficients_mod.populateExecutionTables;
pub const populatePreprocessedCoefficients = preprocessed_coefficients_mod.populatePreprocessedCoefficients;
pub const PreprocessedCoefficientLoad = preprocessed_coefficients_mod.PreprocessedCoefficientLoad;
pub const populateUnreconstructedPreprocessedCoefficients = preprocessed_coefficients_mod.populateUnreconstructedPreprocessedCoefficients;
pub const evaluatePreprocessedCoefficients = preprocessed_coefficients_mod.evaluatePreprocessedCoefficients;

pub const spillPreprocessedEvaluations = preprocessed_storage.spillPreprocessedEvaluations;
pub const spillRetainedMerkleLayers = preprocessed_storage.spillRetainedMerkleLayers;
pub const restoreRetainedMerkleLayers = preprocessed_storage.restoreRetainedMerkleLayers;
pub const restorePreprocessedEvaluations = preprocessed_storage.restorePreprocessedEvaluations;
pub const restoreFixedTablePreprocessedEvaluations = preprocessed_storage.restoreFixedTablePreprocessedEvaluations;

pub const populateProtocolTwiddles = resident_twiddles.populateProtocolTwiddles;
pub const populateForwardTwiddles = resident_twiddles.populateForwardTwiddles;
pub const populateNamedInverseTwiddles = resident_twiddles.populateNamedInverseTwiddles;
pub const populateQuotientInverseTwiddles = resident_twiddles.populateQuotientInverseTwiddles;

const populateInverseTwiddles = resident_twiddles.populateInverseTwiddles;
const populateForwardTwiddleBinding = resident_twiddles.populateForwardTwiddleBinding;
const twiddleBankBinding = resident_twiddles.twiddleBankBinding;
const twiddleBindingForLog = resident_twiddles.twiddleBindingForLog;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;

pub const TranscriptBootstrapValidationOptions = transcript_fixture.TranscriptBootstrapValidationOptions;
pub const validateTranscriptBootstrap = transcript_fixture.validateTranscriptBootstrap;
pub const restoreTranscriptBootstrap = transcript_fixture.restoreTranscriptBootstrap;

pub const prepareFixedTableBatch = fixed_tables.prepareFixedTableBatch;
pub const fixedLookupIndex = fixed_tables.fixedLookupIndex;

pub const MultiplicityFeedBatch = multiplicity_feeds.MultiplicityFeedBatch;
pub const prepareEcOpWitness = witness_prepare.prepareEcOpWitness;
pub const prepareAotWitnessBatch = witness_prepare.prepareAotWitnessBatch;
pub const prepareAotInteractionBatch = witness_prepare.prepareAotInteractionBatch;
pub const AuthenticatedAotWitnessBatches = witness_prepare.AuthenticatedAotWitnessBatches;
pub const prepareAuthenticatedAotWitnessBatches = witness_prepare.prepareAuthenticatedAotWitnessBatches;

pub const prepareMultiplicityFeedBatch = multiplicity_feeds.prepareMultiplicityFeedBatch;

pub fn clearFixedMultiplicities(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !void {
    const bindings = try collectScheduleOrder(allocator, schedule, plan, "FixedMultiplicity");
    defer allocator.free(bindings);
    const ranges = try allocator.alloc([2]u32, bindings.len);
    defer allocator.free(ranges);
    for (bindings, ranges) |binding, *range| {
        if (binding.size_bytes % 4 != 0) return Error.InvalidBindingSize;
        range.* = .{
            try wordOffset(binding),
            std.math.cast(u32, binding.size_bytes / 4) orelse return Error.InvalidBindingSize,
        };
    }
    try metal.clearArenaRanges(resident_arena.buffer, ranges);
}

pub const RecordedBaseInterpolationBatch = trace_interpolation.RecordedBaseInterpolationBatch;
pub const NativeBaseInterpolationBatch = trace_interpolation.NativeBaseInterpolationBatch;
pub const prepareRecordedBaseInterpolation = trace_interpolation.prepareRecordedBaseInterpolation;
pub const prepareNativeBaseInterpolation = trace_interpolation.prepareNativeBaseInterpolation;
const prepareComponentInterpolationGroupsForPurposes = trace_interpolation.prepareComponentInterpolationGroupsForPurposes;
pub const interpolateTraceColumns = trace_interpolation.interpolateTraceColumns;
pub const interpolateAvailablePreprocessedColumns = trace_interpolation.interpolateAvailablePreprocessedColumns;

pub const populateCasmWitnessInputs = witness_inputs.populateCasmWitnessInputs;
pub const populateBuiltinSeedWitnessInputs = witness_inputs.populateBuiltinSeedWitnessInputs;
pub const populateDirectWitnessInput = witness_inputs.populateDirectWitnessInput;

pub const WitnessEdge = witness_execute.WitnessEdge;
pub const prepareCompactWitnessInput = witness_execute.prepareCompactWitnessInput;
pub const WitnessExecutionTelemetry = witness_execute.WitnessExecutionTelemetry;
pub const executeRecordedWitnessGraph = witness_execute.executeRecordedWitnessGraph;
pub const executeNativeEcConsumer = witness_execute.executeNativeEcConsumer;
pub const executeScheduledWitnessGraph = witness_execute.executeScheduledWitnessGraph;
pub const InteractionExecutionTelemetry = interaction_execute.InteractionExecutionTelemetry;
pub const executeScheduledInteractionGraph = interaction_execute.executeScheduledInteractionGraph;
pub const logComponentInteractionDigests = interaction_diagnostics.logComponentInteractionDigests;
pub const logComponentBaseEvalDigests = trace_diagnostics.logComponentBaseEvalDigests;
pub const logInteractionCoefficientDigests = interaction_diagnostics.logInteractionCoefficientDigests;
pub const logLogicalBindingDigest = interaction_diagnostics.logLogicalBindingDigest;

pub const gatherWitnessInput = witness_execute.gatherWitnessInput;

fn prepareCompositionRecipe(
    bindings: PreparedProofBindings,
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    bundle: composition_bundle_mod.Bundle,
    metallib_path: []const u8,
) !protocol_recipes.CompositionRecipe {
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
        "composition_bindings lde_tile_offset={d} lde_tile_size={d} accumulators_offset={d} accumulators_size={d} random_powers_offset={d} random_powers_size={d} descriptors_offset={d} descriptors_size={d} coefficients_first_offset={d} coefficients_count={d}\n",
        .{
            bindings.composition_lde_tile.offset_bytes,
            bindings.composition_lde_tile.size_bytes,
            bindings.composition_accumulators.offset_bytes,
            bindings.composition_accumulators.size_bytes,
            bindings.composition_random_powers.offset_bytes,
            bindings.composition_random_powers.size_bytes,
            bindings.composition_descriptors.offset_bytes,
            bindings.composition_descriptors.size_bytes,
            bindings.composition_coefficients[0].offset_bytes,
            bindings.composition_coefficients.len,
        },
    );
    if (bundle.components.len != bindings.composition_ext_params.len or
        bundle.components.len != bindings.canonical_claimed_sums.len or bundle.total_constraints * 4 != bindings.composition_random_powers.size_bytes / 4)
        return Error.InvalidCardinality;
    const asOffset = struct {
        fn get(binding: arena_plan.Binding) !u32 {
            if (binding.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
            return std.math.cast(u32, binding.offset_bytes / 4) orelse Error.InvalidBindingSize;
        }
    }.get;
    const asWideOffset = struct {
        fn get(binding: arena_plan.Binding) !u64 {
            if (binding.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
            return binding.offset_bytes / 4;
        }
    }.get;
    const bindingLog = struct {
        fn get(binding: arena_plan.Binding) !u32 {
            if (binding.size_bytes < 4 or binding.size_bytes % 4 != 0 or !std.math.isPowerOfTwo(binding.size_bytes / 4))
                return Error.InvalidBindingSize;
            return std.math.log2_int(u64, binding.size_bytes / 4);
        }
    }.get;
    const transcriptOutput = struct {
        fn get(items: []const OrdinalBinding, wanted: u32) !arena_plan.Binding {
            for (items) |item| if (item.ordinal == wanted) return item.binding;
            return Error.MissingBinding;
        }
    }.get;

    var library_config = try composition_config.LibraryConfig.fromProcess(allocator);
    var library_config_live = true;
    defer if (library_config_live) library_config.deinit(allocator);
    const fusion_requested = library_config.fusion_requested;
    const fusion_instruction_cap = library_config.fusion_instruction_cap;
    const fusion_mode = library_config.fusion_mode;
    var library = switch (library_config.library) {
        .source => |source_path| source: {
            const source_bytes = try std.fs.cwd().readFileAlloc(allocator, source_path, 64 * 1024 * 1024);
            defer allocator.free(source_bytes);
            break :source try metal.compileEvalLibrary(source_bytes);
        },
        .metallib => try composition_config.loadAuthenticated(metal, metallib_path),
    };
    library_config.deinit(allocator);
    library_config_live = false;
    defer library.deinit();
    const execution_config = try composition_config.ExecutionConfig.fromProcess(
        allocator,
        bundle.components.len,
        fusion_requested,
    );
    const component_limit = execution_config.component_limit;
    const diagnostic_component = execution_config.diagnostic_component;
    const fusion_enabled = execution_config.fusion_enabled;
    const descriptor_bytes = try resident_arena.bytes(bindings.composition_descriptors);
    const descriptor_aligned: []align(4) u8 = @alignCast(descriptor_bytes);
    const descriptor_words = std.mem.bytesAsSlice(u32, descriptor_aligned);
    @memset(descriptor_words, 0);
    var descriptor_cursor: usize = 0;

    var log_present = [_]bool{false} ** 31;
    for (bundle.components) |component| log_present[component.evaluation_log_size] = true;
    var accumulator_logs = std.ArrayList(u32).empty;
    defer accumulator_logs.deinit(allocator);
    var accumulator_offsets = std.ArrayList(u32).empty;
    defer accumulator_offsets.deinit(allocator);
    var accumulator_relative = [_]?u32{null} ** 31;
    var accumulator_words: u64 = 0;
    for (log_present, 0..) |present, log_size| {
        if (!present) continue;
        accumulator_relative[log_size] = @intCast(accumulator_words);
        try accumulator_logs.append(allocator, @intCast(log_size));
        try accumulator_offsets.append(
            allocator,
            std.math.add(u32, try asOffset(bindings.composition_accumulators), @intCast(accumulator_words)) catch return Error.InvalidBindingSize,
        );
        accumulator_words += @as(u64, 4) << @intCast(log_size);
    }
    if (accumulator_words * 4 != bindings.composition_accumulators.size_bytes) return Error.InvalidBindingSize;

    const lde_plans = try allocator.alloc(metal_runtime.CompositionLdePlan, component_limit);
    defer allocator.free(lde_plans);
    var initialized_ldes: usize = 0;
    defer for (lde_plans[0..initialized_ldes]) |*plan| plan.deinit();
    const eval_batches = try allocator.alloc(metal_runtime.EvalBatchPlan, component_limit);
    defer allocator.free(eval_batches);
    var initialized_batches: usize = 0;
    defer for (eval_batches[0..initialized_batches]) |*plan| plan.deinit();
    var ext_descriptors = std.ArrayList(metal_runtime.CompositionExtParamDescriptor).empty;
    defer ext_descriptors.deinit(allocator);

    const canonical_base = try canonicalTraceTree(allocator, bundle, bindings.named_base_coefficients, 1);
    defer allocator.free(canonical_base);
    const canonical_interaction = try canonicalTraceTree(allocator, bundle, bindings.named_interaction_coefficients, 2);
    defer allocator.free(canonical_interaction);
    const trees = [_][]const arena_plan.Binding{
        bindings.preprocessed_coefficients,
        canonical_base,
        canonical_interaction,
    };
    const tile_base = try asOffset(bindings.composition_lde_tile);
    const accumulator_base = try asOffset(bindings.composition_accumulators);
    const random_powers = try asOffset(bindings.composition_random_powers);
    const relation_z = try asOffset(bindings.relation_z);
    const relation_alpha = try asOffset(bindings.relation_alpha_powers);

    var composition_original_parts: usize = 0;
    var composition_dispatch_slices: usize = 0;
    for (bundle.components[0..component_limit], 0..) |component, component_index| {
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("composition_prepare component={s} instance={d} index={d} eval_log={d}\n", .{
                component.label, component.instance, component_index, component.evaluation_log_size,
            });
        var sources = std.ArrayList(arena_plan.Binding).empty;
        defer sources.deinit(allocator);
        for (component.preprocessed_indices) |column| {
            if (column >= trees[0].len) return Error.InvalidBindingSize;
            try sources.append(allocator, trees[0][column]);
        }
        for ([_]u32{ 1, 2 }) |tree| {
            var found = false;
            for (component.trace_spans) |span| {
                if (span.tree != tree) continue;
                if (found or span.start > span.end or span.end > trees[tree].len) return Error.InvalidBindingSize;
                found = true;
                try sources.appendSlice(allocator, trees[tree][span.start..span.end]);
            }
            if (!found) return Error.InvalidBindingSize;
        }
        const row_count = @as(u32, 1) << @intCast(component.evaluation_log_size);
        const source_offsets = try allocator.alloc(u64, sources.items.len);
        defer allocator.free(source_offsets);
        const source_logs = try allocator.alloc(u32, sources.items.len);
        defer allocator.free(source_logs);
        const destination_offsets = try allocator.alloc(u32, sources.items.len);
        defer allocator.free(destination_offsets);
        for (sources.items, source_offsets, source_logs, destination_offsets, 0..) |source, *source_offset, *source_log, *destination, index| {
            source_offset.* = try asWideOffset(source);
            source_log.* = try bindingLog(source);
            if (source_log.* > component.evaluation_log_size) {
                std.debug.print(
                    "composition source exceeds domain: {s}[{}] local={} source={} log={} evaluation_log={} spans={any}\n",
                    .{ component.label, component.instance, index, source.logical_id, source_log.*, component.evaluation_log_size, component.trace_spans },
                );
                return Error.InvalidBindingSize;
            }
            destination.* = std.math.add(u32, tile_base, @intCast(index * @as(usize, row_count))) catch return Error.InvalidBindingSize;
            if (diagnostic_component == component_index) std.debug.print(
                "composition_source_binding component_index={} local_index={} logical_id={} source_offset={} source_log={} destination_offset={} evaluation_log={}\n",
                .{ component_index, index, source.logical_id, source_offset.*, source_log.*, destination.*, component.evaluation_log_size },
            );
        }
        if (@as(u64, sources.items.len) * row_count * 4 > bindings.composition_lde_tile.size_bytes)
            return Error.InvalidBindingSize;
        lde_plans[component_index] = try metal.prepareCompositionLde(
            source_offsets,
            source_logs,
            destination_offsets,
            component.evaluation_log_size,
            try twiddleOffsetForLog(bindings.forward_twiddles, component.evaluation_log_size),
        );
        initialized_ldes += 1;

        const trace_offsets_at = descriptor_cursor;
        descriptor_cursor += sources.items.len;
        const interaction_offsets_at = descriptor_cursor;
        descriptor_cursor += 3;
        const denominators_at = descriptor_cursor;
        descriptor_cursor += component.denominator_inverses.len;
        if (descriptor_cursor > descriptor_words.len) return Error.InvalidBindingSize;
        @memcpy(descriptor_words[trace_offsets_at .. trace_offsets_at + sources.items.len], destination_offsets);
        const preprocessed_count = component.preprocessed_indices.len;
        var base_count: usize = 0;
        for (component.trace_spans) |span| {
            if (span.tree == 1) base_count = @intCast(span.end - span.start);
        }
        descriptor_words[interaction_offsets_at] = 0;
        descriptor_words[interaction_offsets_at + 1] = @intCast(preprocessed_count);
        descriptor_words[interaction_offsets_at + 2] = @intCast(preprocessed_count + base_count);
        @memcpy(descriptor_words[denominators_at .. denominators_at + component.denominator_inverses.len], component.denominator_inverses);

        const ext_binding = bindings.composition_ext_params[component_index];
        if (ext_binding.size_bytes < @as(u64, component.ext_sources.len) * 16) return Error.InvalidBindingSize;
        for (component.ext_sources, 0..) |source, slot| {
            const destination = std.math.add(u32, try asOffset(ext_binding), @intCast(slot * 4)) catch return Error.InvalidBindingSize;
            const descriptor: metal_runtime.CompositionExtParamDescriptor = switch (source) {
                .constant => |value| .{ .destination = destination, .kind = 0, .source = 0, .scale = 1, .constant = value },
                .lookup_z => .{ .destination = destination, .kind = 1, .source = relation_z, .scale = 1, .constant = .{ 0, 0, 0, 0 } },
                .lookup_alpha_power => |power| .{ .destination = destination, .kind = 1, .source = relation_alpha + power * 4, .scale = 1, .constant = .{ 0, 0, 0, 0 } },
                .lookup_alpha_power_scaled => |scaled| .{ .destination = destination, .kind = 1, .source = relation_alpha + scaled.power * 4, .scale = scaled.scale, .constant = .{ 0, 0, 0, 0 } },
                .claimed_sum_scaled => blk: {
                    const scale = M31.fromCanonical(@as(u32, 1) << @intCast(component.trace_log_size)).inv() catch return Error.InvalidBindingSize;
                    break :blk .{ .destination = destination, .kind = 1, .source = try asOffset(bindings.canonical_claimed_sums[component_index]), .scale = scale.v, .constant = .{ 0, 0, 0, 0 } };
                },
            };
            try ext_descriptors.append(allocator, descriptor);
        }

        composition_original_parts += component.parts.len;
        const plans = try allocator.alloc(metal_runtime.EvalPlan, component.parts.len);
        defer allocator.free(plans);
        var plans_initialized: usize = 0;
        defer for (plans[0..plans_initialized]) |*plan| plan.deinit();
        const accumulator_relative_offset = accumulator_relative[component.evaluation_log_size] orelse return Error.InvalidBindingSize;
        const fused_parts = try allocator.alloc(eval_codegen.FusedPart, component.parts.len);
        defer allocator.free(fused_parts);
        for (component.parts, fused_parts) |part, *fused| fused.* = .{
            .program = part.program,
            .rc_base = part.rc_base,
        };
        var hybrid_partition: ?eval_codegen.FusionPartition = null;
        defer if (hybrid_partition) |*partition| partition.deinit();
        if (fusion_enabled and fusion_mode == .experimental_hybrid_source_diagnostic)
            hybrid_partition = try eval_codegen.hybridFusionPartition(
                allocator,
                fused_parts,
                .{},
            );
        var part_start: usize = 0;
        var hybrid_slice_index: usize = 0;
        while (part_start < component.parts.len) {
            const part_end = if (!fusion_enabled)
                part_start + 1
            else switch (fusion_mode) {
                .capped => try eval_codegen.fusionGroupEnd(
                    fused_parts,
                    part_start,
                    fusion_instruction_cap,
                ),
                .experimental_hybrid_source_diagnostic => end: {
                    const slice = hybrid_partition.?.slices[hybrid_slice_index];
                    if (slice.start != part_start) return Error.InvalidCardinality;
                    hybrid_slice_index += 1;
                    break :end slice.end;
                },
            };
            const part = component.parts[part_start];
            const name = try eval_codegen.fusionSliceKernelName(
                allocator,
                fused_parts,
                .{
                    .start = part_start,
                    .end = part_end,
                    .operations = 0,
                    .source_bytes = 0,
                },
            );
            defer allocator.free(name);
            var slice_operations: usize = 0;
            for (fused_parts[part_start..part_end]) |fused|
                slice_operations += eval_codegen.fusionOperationCount(fused.program);
            var pipeline_timer = try std.time.Timer.start();
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
                "composition_prepare_slice component_index={} slice_index={} first_part={} part_count={} operations={} kernel={s} begin\n",
                .{
                    component_index,
                    plans_initialized,
                    part_start,
                    part_end - part_start,
                    slice_operations,
                    name,
                },
            );
            plans[plans_initialized] = try metal.prepareEvalFromLibrary(library, name, .{
                .trace_offsets = try descriptorWordOffset(bindings.composition_descriptors, trace_offsets_at),
                .interaction_offsets = try descriptorWordOffset(bindings.composition_descriptors, interaction_offsets_at),
                .base_params = 0,
                .ext_params = try asOffset(ext_binding),
                .random_coeffs = random_powers,
                .denom_inv = try descriptorWordOffset(bindings.composition_descriptors, denominators_at),
                .coordinates = .{
                    accumulator_base + accumulator_relative_offset,
                    accumulator_base + accumulator_relative_offset + row_count,
                    accumulator_base + accumulator_relative_offset + row_count * 2,
                    accumulator_base + accumulator_relative_offset + row_count * 3,
                },
                .row_count = row_count,
                .trace_log_size = component.trace_log_size,
                .domain_log_size = component.trace_log_size,
                .rc_base = try compositionRandomCoefficientBase(
                    component.random_coefficient_offset,
                    part.rc_base,
                ),
            });
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
                "composition_prepare_slice component_index={} slice_index={} wall_ms={d:.3} done\n",
                .{
                    component_index,
                    plans_initialized,
                    @as(f64, @floatFromInt(pipeline_timer.read())) / std.time.ns_per_ms,
                },
            );
            plans_initialized += 1;
            part_start = part_end;
        }
        if (hybrid_partition) |partition|
            if (hybrid_slice_index != partition.slices.len)
                return Error.InvalidCardinality;
        composition_dispatch_slices += plans_initialized;
        eval_batches[component_index] = try metal.prepareEvalBatch(plans[0..plans_initialized]);
        initialized_batches += 1;
    }

    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
        "composition_fusion enabled={} mode={s} instruction_cap={} original_parts={} dispatch_slices={}\n",
        .{
            fusion_enabled,
            @tagName(fusion_mode),
            if (fusion_enabled) fusion_instruction_cap else @as(usize, 0),
            composition_original_parts,
            composition_dispatch_slices,
        },
    );

    // Persist the pipeline states added while resolving either an AOT metallib
    // or a source-compiled library. Without this, every prover process rebuilds
    // every AIR pipeline before composition.
    try library.serialize();

    var inputs = try metal.prepareCompositionInputs(
        ext_descriptors.items,
        try asOffset(try transcriptOutput(bindings.transcript_outputs, 2)),
        random_powers,
        @intCast(bundle.total_constraints),
    );
    defer inputs.deinit();
    var front = try metal.prepareCompositionFront(
        inputs,
        lde_plans,
        eval_batches,
        accumulator_base,
        @intCast(accumulator_words),
    );
    errdefer front.deinit();
    var output_offsets: [8]u32 = undefined;
    var output_bindings: [8]arena_plan.Binding = undefined;
    for (bindings.composition_coefficients, &output_offsets, &output_bindings) |binding, *offset, *output_binding| {
        offset.* = try asOffset(binding);
        output_binding.* = binding;
    }
    const max_rows = @as(u32, 1) << @intCast(bundle.max_evaluation_log_size);
    const scale = M31.fromCanonical(max_rows).inv() catch return Error.InvalidBindingSize;
    var finalize = try metal.prepareCompositionFinalize(
        accumulator_offsets.items,
        accumulator_logs.items,
        try asOffset(bindings.inverse_twiddles),
        output_offsets,
        scale.v,
    );
    errdefer finalize.deinit();
    return protocol_recipes.CompositionRecipe.init(
        allocator,
        metal,
        resident_arena,
        front,
        finalize,
        output_bindings,
        component_limit == bundle.components.len,
    );
}

fn descriptorWordOffset(binding: arena_plan.Binding, relative: usize) !u32 {
    if (binding.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
    return std.math.add(u32, std.math.cast(u32, binding.offset_bytes / 4) orelse return Error.InvalidBindingSize, @intCast(relative)) catch Error.InvalidBindingSize;
}

fn compositionRandomCoefficientBase(component_offset: u32, part_offset: u32) !u32 {
    return std.math.add(u32, component_offset, part_offset) catch Error.InvalidBindingSize;
}

const wordOffset = resident_binding.wordOffset;

fn writeBindingOffsets(
    resident_arena: *arena_plan.ResidentArena,
    destination: arena_plan.Binding,
    sources: []const arena_plan.Binding,
) !void {
    const bytes = try resident_arena.bytes(destination);
    if (bytes.len % 4 != 0 or bytes.len < sources.len * 4) return Error.InvalidBindingSize;
    const aligned: []align(4) u8 = @alignCast(bytes);
    const words = std.mem.bytesAsSlice(u32, aligned);
    @memset(words, 0);
    for (sources, words[0..sources.len]) |source, *offset| offset.* = try wordOffset(source);
}

fn writeWideWordOffset(words: []u32, index: usize, offset_words: u64) !void {
    const base = std.math.mul(usize, index, 2) catch return Error.InvalidBindingSize;
    if (base + 2 > words.len) return Error.InvalidBindingSize;
    words[base] = @truncate(offset_words);
    words[base + 1] = @truncate(offset_words >> 32);
}

fn writeWideBindingOffsets(
    resident_arena: *arena_plan.ResidentArena,
    destination: arena_plan.Binding,
    sources: []const arena_plan.Binding,
) !void {
    const bytes = try resident_arena.bytes(destination);
    if (bytes.len % 4 != 0 or bytes.len < sources.len * 2 * @sizeOf(u32))
        return Error.InvalidBindingSize;
    const aligned: []align(4) u8 = @alignCast(bytes);
    const words = std.mem.bytesAsSlice(u32, aligned);
    @memset(words, 0);
    for (sources, 0..) |source, index| {
        if (source.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
        try writeWideWordOffset(words, index, source.offset_bytes / 4);
    }
}

test "Cairo decommit pointer entries preserve word offsets above 16 GiB" {
    var words = [_]u32{0} ** 4;
    const high_offset = (@as(u64, 1) << 32) + 0x12345678;
    try writeWideWordOffset(&words, 1, high_offset);
    try std.testing.expectEqual(@as(u32, 0x12345678), words[2]);
    try std.testing.expectEqual(@as(u32, 1), words[3]);
}

fn writePreprocessedOffsets(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    identities: []const []u8,
    destination: arena_plan.Binding,
) !void {
    const sources = try collectPreprocessedBindings(fixed_bundle.allocator, schedule, plan, fixed_bundle, identities);
    defer fixed_bundle.allocator.free(sources);
    try writeBindingOffsets(resident_arena, destination, sources);
}

fn bindingWords(
    resident_arena: *arena_plan.ResidentArena,
    binding: arena_plan.Binding,
) ![]u32 {
    const bytes = try resident_arena.bytes(binding);
    if (bytes.len % 4 != 0) return Error.InvalidBindingSize;
    const aligned: []align(4) u8 = @alignCast(bytes);
    return std.mem.bytesAsSlice(u32, aligned);
}

fn populateTraceRetainedPointers(
    resident_arena: *arena_plan.ResidentArena,
    tree: DecommitTraceTreeBindings,
    retained_bottom_first: []const arena_plan.Binding,
) !void {
    const first_retained_log = tree.leaf_log - tree.unretained;
    if (retained_bottom_first.len != first_retained_log + 1) return Error.InvalidCardinality;
    const words = try bindingWords(resident_arena, tree.retained_pointers);
    if (words.len < (tree.leaf_log + 1) * 2) return Error.InvalidBindingSize;
    @memset(words, 0);
    for (0..first_retained_log + 1) |level| {
        const retained_index = first_retained_log - level;
        const retained = retained_bottom_first[retained_index];
        if (retained.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
        try writeWideWordOffset(words, level, retained.offset_bytes / 4);
    }
}

fn populateFriRetainedPointers(
    resident_arena: *arena_plan.ResidentArena,
    tree: DecommitFriTreeBindings,
    retained_root_first: []const arena_plan.Binding,
) !void {
    if (retained_root_first.len != tree.leaf_log + 1) return Error.InvalidCardinality;
    try writeWideBindingOffsets(resident_arena, tree.retained_pointers, retained_root_first);
}

fn populateFriCoordinatePointers(
    resident_arena: *arena_plan.ResidentArena,
    tree: DecommitFriTreeBindings,
    evaluation: arena_plan.Binding,
) !void {
    const rows = @as(u64, 1) << @intCast(tree.leaf_log + 2);
    if (evaluation.size_bytes != rows * 16) return Error.InvalidBindingSize;
    const words = try bindingWords(resident_arena, tree.coordinate_pointers);
    if (words.len < 8) return Error.InvalidBindingSize;
    @memset(words, 0);
    if (evaluation.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
    const base = evaluation.offset_bytes / 4;
    for (0..4) |coordinate| {
        const offset = std.math.add(u64, base, @as(u64, coordinate) * rows) catch
            return Error.InvalidBindingSize;
        try writeWideWordOffset(words, coordinate, offset);
    }
}

fn populateSparseOffsets(
    resident_arena: *arena_plan.ResidentArena,
    sparse_indices: arena_plan.Binding,
    sparse_offsets: arena_plan.Binding,
    unretained: u32,
) !void {
    if (unretained == 0 or unretained > 4) return Error.InvalidBindingSize;
    const words = try bindingWords(resident_arena, sparse_offsets);
    if (words.len < unretained) return Error.InvalidBindingSize;
    @memset(words, 0);
    var offset: u64 = 0;
    var capacity: u64 = 70 * (@as(u64, 1) << @intCast(unretained));
    for (0..unretained) |distance| {
        words[distance] = std.math.cast(u32, offset) orelse return Error.InvalidBindingSize;
        offset += capacity;
        capacity >>= 1;
    }
    if (offset * 4 > sparse_indices.size_bytes) return Error.InvalidBindingSize;
}

fn executeDecommitTraceLdeGroup(
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    twiddles: arena_plan.Binding,
    tile: arena_plan.Binding,
    group: DecommitTraceGroupBindings,
    coefficients: []const arena_plan.Binding,
) !f64 {
    if (coefficients.len != group.column_count or coefficients.len == 0 or coefficients.len > 16)
        return Error.InvalidCardinality;
    var source_offsets: [16]u64 = undefined;
    var source_logs: [16]u32 = undefined;
    var output_offsets: [16]u32 = undefined;
    var output_logs: [16]u32 = undefined;
    var tile_cursor: u64 = 0;
    var max_evaluation_log: u32 = 0;
    for (coefficients, 0..) |source, index| {
        if (source.size_bytes < 32 or source.size_bytes % 4 != 0 or
            !std.math.isPowerOfTwo(source.size_bytes / 4))
            return Error.InvalidBindingSize;
        const source_log: u32 = std.math.log2_int(u64, source.size_bytes / 4);
        const evaluation_log = source_log + 1;
        const evaluation_words = @as(u64, 1) << @intCast(evaluation_log);
        if (tile_cursor + evaluation_words > tile.size_bytes / 4) return Error.InvalidBindingSize;
        source_offsets[index] = source.offset_bytes / 4;
        source_logs[index] = source_log;
        output_offsets[index] = std.math.cast(u32, tile.offset_bytes / 4 + tile_cursor) orelse
            return Error.InvalidBindingSize;
        output_logs[index] = evaluation_log;
        max_evaluation_log = @max(max_evaluation_log, evaluation_log);
        tile_cursor += evaluation_words;
    }

    const evaluation_pointer_words = try bindingWords(resident_arena, group.evaluation_pointers);
    const evaluation_log_words = try bindingWords(resident_arena, group.evaluation_logs);
    if (evaluation_pointer_words.len < coefficients.len * 2 or evaluation_log_words.len < coefficients.len)
        return Error.InvalidBindingSize;
    @memset(evaluation_pointer_words, 0);
    @memset(evaluation_log_words, 0);
    for (output_offsets[0..coefficients.len], 0..) |offset, index|
        try writeWideWordOffset(evaluation_pointer_words, index, offset);
    @memcpy(evaluation_log_words[0..coefficients.len], output_logs[0..coefficients.len]);
    if (group.coefficients) |coefficient_bindings| {
        try writeWideBindingOffsets(resident_arena, coefficient_bindings.pointers, coefficients);
        const size_words = try bindingWords(resident_arena, coefficient_bindings.sizes);
        const output_pointer_words = try bindingWords(resident_arena, coefficient_bindings.lde_output_pointers);
        if (size_words.len < coefficients.len or output_pointer_words.len < coefficients.len * 2)
            return Error.InvalidBindingSize;
        @memset(size_words, 0);
        @memset(output_pointer_words, 0);
        for (coefficients, size_words[0..coefficients.len]) |source, *size|
            size.* = std.math.cast(u32, source.size_bytes / 4) orelse return Error.InvalidBindingSize;
        for (output_offsets[0..coefficients.len], 0..) |offset, index|
            try writeWideWordOffset(output_pointer_words, index, offset);
    }

    var gpu_ms: f64 = 0;
    for (4..max_evaluation_log + 1) |evaluation_log_usize| {
        const evaluation_log: u32 = @intCast(evaluation_log_usize);
        var filtered_sources: [16]u64 = undefined;
        var filtered_logs: [16]u32 = undefined;
        var filtered_outputs: [16]u32 = undefined;
        var filtered_count: usize = 0;
        for (output_logs[0..coefficients.len], 0..) |candidate_log, index| {
            if (candidate_log != evaluation_log) continue;
            filtered_sources[filtered_count] = source_offsets[index];
            filtered_logs[filtered_count] = source_logs[index];
            filtered_outputs[filtered_count] = output_offsets[index];
            filtered_count += 1;
        }
        if (filtered_count == 0) continue;
        const evaluation_twiddles = twiddleBankBinding(twiddles, evaluation_log);
        var lde = try metal.prepareCompositionLde(
            filtered_sources[0..filtered_count],
            filtered_logs[0..filtered_count],
            filtered_outputs[0..filtered_count],
            evaluation_log,
            try twiddleOffsetForLog(evaluation_twiddles, evaluation_log),
        );
        defer lde.deinit();
        gpu_ms += try metal.compositionLdePrepared(resident_arena.buffer, lde);
    }
    return gpu_ms;
}

fn collectAssembly(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) ![]arena_plan.Binding {
    var result = std.ArrayList(arena_plan.Binding).empty;
    errdefer result.deinit(allocator);
    for (schedule) |entry| {
        const name = try purpose(entry);
        if (!std.mem.startsWith(u8, name, "Decommit") and
            !std.mem.startsWith(u8, name, "Transcript") and
            !std.mem.startsWith(u8, name, "Pow") and
            !std.mem.eql(u8, name, "ProofBytes")) continue;
        try result.append(allocator, plan.binding(try logicalId(entry)) catch return Error.MissingBinding);
    }
    if (result.items.len == 0) return Error.MissingBinding;
    return result.toOwnedSlice(allocator);
}

fn executeStreamingCommitment(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    coefficients: []const arena_plan.Binding,
    twiddles: arena_plan.Binding,
    tree_index: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
) !CommitmentTelemetry {
    return executeStreamingCommitmentWithMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        coefficients,
        twiddles,
        tree_index,
        leaf_seed,
        node_seed,
        .automatic,
    );
}

pub const StreamingCommitmentBenchmarkMode = enum { automatic, synchronous };

/// Bounded benchmark hook for the exact production commitment graph. Normal
/// proving always enters through executeStreamingCommitment in automatic mode.
pub fn executeStreamingCommitmentBenchmark(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    coefficients: []const arena_plan.Binding,
    twiddles: arena_plan.Binding,
    tree_index: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    mode: StreamingCommitmentBenchmarkMode,
) !CommitmentTelemetry {
    return executeStreamingCommitmentWithMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        coefficients,
        twiddles,
        tree_index,
        leaf_seed,
        node_seed,
        mode,
    );
}

fn executeStreamingCommitmentWithMode(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    coefficients: []const arena_plan.Binding,
    twiddles: arena_plan.Binding,
    tree_index: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    mode: StreamingCommitmentBenchmarkMode,
) !CommitmentTelemetry {
    const group_descriptors = try collectTreePurpose(allocator, schedule, plan, "CommitColumnLogSizes", tree_index);
    defer allocator.free(group_descriptors);
    const tile_items = try collectTreePurpose(allocator, schedule, plan, "CommitLdeTile", tree_index);
    defer allocator.free(tile_items);
    const leaf_items = try collectTreePurpose(allocator, schedule, plan, "MerkleLeafState", tree_index);
    defer allocator.free(leaf_items);
    if (tile_items.len != 1 or leaf_items.len != 1) return Error.InvalidCardinality;
    const tile = tile_items[0];
    const leaf_state = leaf_items[0];
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
        std.debug.print("commit_prepare tree={d} coefficients={d} twiddle_offset={d} twiddle_size={d} tile_offset={d} tile_size={d} leaf_offset={d} leaf_size={d}\n", .{
            tree_index, coefficients.len, twiddles.offset_bytes, twiddles.size_bytes, tile.offset_bytes, tile.size_bytes, leaf_state.offset_bytes, leaf_state.size_bytes,
        });
    const scratch_items = collectTreePurpose(allocator, schedule, plan, "MerkleLayerScratch", tree_index) catch &[_]arena_plan.Binding{};
    defer if (scratch_items.len != 0) allocator.free(scratch_items);
    const retained = try collectTreePurpose(allocator, schedule, plan, "RetainedMerkleLayers", tree_index);
    defer allocator.free(retained);
    if (leaf_state.size_bytes % 32 != 0 or !std.math.isPowerOfTwo(leaf_state.size_bytes / 32)) return Error.InvalidBindingSize;
    const lifting_log: u32 = std.math.log2_int(u64, leaf_state.size_bytes / 32);
    var coefficient_cursor: usize = 0;
    var gpu_ms: f64 = 0;
    var lde_gpu_ms: f64 = 0;
    var leaf_gpu_ms: f64 = 0;
    var parent_gpu_ms: f64 = 0;
    const use_compact_leaf_state = !std.process.hasEnvVarConstant("STWO_ZIG_SN2_COMMIT_FULL_LOG_LEAVES") and
        !std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_STEPS");
    if (use_compact_leaf_state and scratch_items.len != 1) return Error.InvalidCardinality;
    const requires_intermediate_visibility = std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_LDE_DIGESTS") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_STEPS") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPEAT_COMMIT_LDE") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE");
    var command_epoch: ?metal_runtime.CommandEpoch = if (mode == .automatic and use_compact_leaf_state and !requires_intermediate_visibility)
        try metal.beginCommandEpoch(resident_arena.buffer)
    else
        null;
    defer if (command_epoch) |*epoch| epoch.deinit();
    var previous_group_log: ?u32 = null;
    var leaf_state_log: ?u32 = null;
    var command_epoch_stats: ?metal_runtime.CommandEpochStats = null;
    for (group_descriptors, 0..) |descriptor, group_index| {
        const width = std.math.cast(usize, descriptor.size_bytes / 4) orelse return Error.InvalidBindingSize;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS") and group_index % 32 == 0)
            std.debug.print("commit_progress tree={d} group={d} coefficient_cursor={d} gpu_ms={d:.3}\n", .{
                tree_index, group_index, coefficient_cursor, gpu_ms,
            });
        if (width == 0 or width > 16 or coefficient_cursor + width > coefficients.len) {
            std.debug.print("commit_group_invalid tree={d} group={d} width={d} cursor={d} coefficients={d}\n", .{
                tree_index, group_index, width, coefficient_cursor, coefficients.len,
            });
            return Error.InvalidCardinality;
        }
        const group = coefficients[coefficient_cursor .. coefficient_cursor + width];
        var output_offsets: [16]u32 = undefined;
        var output_logs: [16]u32 = undefined;
        var tile_cursor: u64 = 0;
        for (group, 0..) |source, index| {
            if (source.size_bytes < 64 or !std.math.isPowerOfTwo(source.size_bytes / 4)) {
                std.debug.print("commit_source_size_invalid tree={d} group={d} logical_id={d} offset={d} size={d}\n", .{
                    tree_index, group_index, source.logical_id, source.offset_bytes, source.size_bytes,
                });
                return Error.InvalidBindingSize;
            }
            const coefficient_log: u32 = std.math.log2_int(u64, source.size_bytes / 4);
            const evaluation_log = coefficient_log + 1;
            const evaluation_words = @as(u64, 1) << @intCast(evaluation_log);
            if (tile_cursor + evaluation_words > tile.size_bytes / 4) {
                std.debug.print("commit_tile_size_invalid tree={d} group={d} cursor={d} evaluation_words={d} tile_words={d}\n", .{
                    tree_index, group_index, tile_cursor, evaluation_words, tile.size_bytes / 4,
                });
                return Error.InvalidBindingSize;
            }
            output_offsets[index] = std.math.cast(u32, tile.offset_bytes / 4 + tile_cursor) orelse {
                std.debug.print("commit_tile_offset_overflow tree={d} group={d} index={d} offset={d}\n", .{
                    tree_index, group_index, index, tile.offset_bytes + tile_cursor * 4,
                });
                return Error.InvalidBindingSize;
            };
            output_logs[index] = evaluation_log;
            tile_cursor += evaluation_words;
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_SOURCE_DIGESTS"))
            try commitment_telemetry.logCommitSourceDigests(resident_arena, coefficient_cursor, group);
        if (tree_index == 2 and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE") and
            coefficient_cursor <= 2241 and 2241 < coefficient_cursor + width)
        {
            const local_index = 2241 - coefficient_cursor;
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-pre-group-source.u32le", .{});
            defer file.close();
            try file.writeAll(try resident_arena.bytes(group[local_index]));
        }
        for (4..lifting_log + 1) |evaluation_log_usize| {
            const evaluation_log: u32 = @intCast(evaluation_log_usize);
            var sources = std.ArrayList(u64).empty;
            defer sources.deinit(allocator);
            var logs = std.ArrayList(u32).empty;
            defer logs.deinit(allocator);
            var outputs = std.ArrayList(u32).empty;
            defer outputs.deinit(allocator);
            for (group, output_offsets[0..width], output_logs[0..width]) |source, output, log_size| {
                if (log_size != evaluation_log) continue;
                try sources.append(allocator, source.offset_bytes / 4);
                try logs.append(allocator, std.math.log2_int(u64, source.size_bytes / 4));
                try outputs.append(allocator, output);
            }
            if (sources.items.len == 0) continue;
            const evaluation_twiddles = twiddleBankBinding(twiddles, evaluation_log);
            const twiddle_offset = twiddleOffsetForLog(evaluation_twiddles, evaluation_log) catch {
                std.debug.print("commit_twiddle_offset_invalid tree={d} group={d} evaluation_log={d} offset={d} size={d}\n", .{
                    tree_index, group_index, evaluation_log, evaluation_twiddles.offset_bytes, evaluation_twiddles.size_bytes,
                });
                return Error.InvalidBindingSize;
            };
            var lde = try metal.prepareCompositionLde(sources.items, logs.items, outputs.items, evaluation_log, twiddle_offset);
            defer lde.deinit();
            const elapsed_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                try epoch.encodeCompositionLde(lde);
                break :epoch_time 0;
            } else try metal.compositionLdePrepared(resident_arena.buffer, lde);
            gpu_ms += elapsed_gpu_ms;
            lde_gpu_ms += elapsed_gpu_ms;
            if (group_index == 48 and std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPEAT_COMMIT_LDE")) {
                const first_digest = commitment_telemetry.sampleCommitOutputs(resident_arena, outputs.items, evaluation_log);
                const repeated_gpu_ms = try metal.compositionLdePrepared(resident_arena.buffer, lde);
                gpu_ms += repeated_gpu_ms;
                lde_gpu_ms += repeated_gpu_ms;
                const second_digest = commitment_telemetry.sampleCommitOutputs(resident_arena, outputs.items, evaluation_log);
                std.debug.print(
                    "commit_lde_repeat evaluation_log={} first={x:0>16} second={x:0>16}\n",
                    .{ evaluation_log, first_digest, second_digest },
                );
            }
        }
        if (tree_index == 2 and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE") and
            coefficient_cursor <= 2241 and 2241 < coefficient_cursor + width)
        {
            const local_index = 2241 - coefficient_cursor;
            const source = group[local_index];
            const diagnostic_source = group[local_index - 1];
            @memcpy(
                try resident_arena.bytes(diagnostic_source),
                try resident_arena.bytes(source),
            );
            const evaluation_log = output_logs[local_index];
            const evaluation_twiddles = twiddleBankBinding(twiddles, evaluation_log);
            const sources = [_]u64{diagnostic_source.offset_bytes / 4};
            const logs = [_]u32{std.math.log2_int(u64, diagnostic_source.size_bytes / 4)};
            const outputs = [_]u32{output_offsets[local_index]};
            var repair = try metal.prepareCompositionLde(
                &sources,
                &logs,
                &outputs,
                evaluation_log,
                try twiddleOffsetForLog(evaluation_twiddles, evaluation_log),
            );
            defer repair.deinit();
            const repair_gpu_ms = try metal.compositionLdePrepared(resident_arena.buffer, repair);
            gpu_ms += repair_gpu_ms;
            lde_gpu_ms += repair_gpu_ms;
            const lde_words = @as(usize, 1) << @intCast(evaluation_log);
            const arena_bytes: [*]const u8 = @ptrCast(resident_arena.buffer.contents);
            const lde_bytes = arena_bytes[@as(usize, outputs[0]) * 4 ..][0 .. lde_words * 4];
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-metal-lde.u32le", .{});
            defer file.close();
            try file.writeAll(lde_bytes);

            const source_bytes = try resident_arena.bytes(source);
            const source_file = try std.fs.createFileAbsolute("/tmp/sn2-column613-commit-source.u32le", .{});
            defer source_file.close();
            try source_file.writeAll(source_bytes);
            const source_words: []align(1) const u32 = std.mem.bytesAsSlice(u32, source_bytes);
            const coefficient_values = try allocator.alloc(M31, source_words.len);
            for (source_words, coefficient_values) |word, *value|
                value.* = M31.fromCanonical(word % 0x7fffffff);
            var cpu_coefficients = try circle_poly_mod.CircleCoefficients.initOwned(coefficient_values);
            defer cpu_coefficients.deinit(allocator);
            const cpu_lde = try cpu_coefficients.evaluate(
                allocator,
                canonic_circle_mod.CanonicCoset.new(evaluation_log).circleDomain(),
            );
            defer allocator.free(@constCast(cpu_lde.values));
            const cpu_file = try std.fs.createFileAbsolute("/tmp/sn2-column613-repair-cpu-lde.u32le", .{});
            defer cpu_file.close();
            try cpu_file.writeAll(std.mem.sliceAsBytes(cpu_lde.values));
            @memcpy(
                @constCast(lde_bytes),
                std.mem.sliceAsBytes(cpu_lde.values),
            );
            const repaired_file = try std.fs.createFileAbsolute("/tmp/sn2-column613-repaired-lde.u32le", .{});
            defer repaired_file.close();
            try repaired_file.writeAll(lde_bytes);
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_LDE_DIGESTS"))
            commitment_telemetry.logCommitLdeDigests(
                resident_arena,
                coefficient_cursor,
                group,
                output_offsets[0..width],
                output_logs[0..width],
            );
        var group_log: u32 = 0;
        for (output_logs[0..width]) |output_log| group_log = @max(group_log, output_log);
        if (group_log > lifting_log or (previous_group_log != null and group_log < previous_group_log.?))
            return Error.InvalidBindingSize;
        const is_final = group_index + 1 == group_descriptors.len;
        const elapsed_leaf_gpu_ms = if (use_compact_leaf_state) compact: {
            const destination_log = if (is_final) lifting_log else group_log;
            var source_state_offset = try wordOffset(leaf_state);
            var source_state_log = leaf_state_log orelse destination_log;
            if (leaf_state_log) |materialized_log| {
                if (destination_log < materialized_log) return Error.InvalidBindingSize;
                if (destination_log > materialized_log) {
                    const scratch = scratch_items[0];
                    const snapshot_words = (@as(u64, 1) << @intCast(materialized_log)) * 8;
                    if (snapshot_words > scratch.size_bytes / 4 or snapshot_words > std.math.maxInt(u32))
                        return Error.InvalidBindingSize;
                    const ranges = [_]metal_runtime.ArenaCopyRange{.{
                        .source_word_offset = leaf_state.offset_bytes / 4,
                        .destination_word_offset = scratch.offset_bytes / 4,
                        .word_count = @intCast(snapshot_words),
                    }};
                    var copy = try metal.prepareArenaCopies(&ranges);
                    defer copy.deinit();
                    const copy_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                        try epoch.encodeArenaCopy(copy);
                        break :epoch_time 0;
                    } else try metal.arenaCopyPrepared(resident_arena.buffer, copy);
                    gpu_ms += copy_gpu_ms;
                    leaf_gpu_ms += copy_gpu_ms;
                    source_state_offset = try wordOffset(scratch);
                    source_state_log = materialized_log;
                }
            }
            const elapsed = if (command_epoch) |*epoch| epoch_time: {
                try epoch.encodeCompactLeaf(
                    output_offsets[0..width],
                    output_logs[0..width],
                    source_state_offset,
                    source_state_log,
                    try wordOffset(leaf_state),
                    destination_log,
                    @intCast(coefficient_cursor),
                    is_final,
                    0,
                    leaf_seed,
                );
                break :epoch_time 0;
            } else try metal.leafAbsorbCompact(
                resident_arena.buffer,
                output_offsets[0..width],
                output_logs[0..width],
                source_state_offset,
                source_state_log,
                try wordOffset(leaf_state),
                destination_log,
                @intCast(coefficient_cursor),
                is_final,
                0,
                leaf_seed,
            );
            leaf_state_log = destination_log;
            break :compact elapsed;
        } else try metal.leafAbsorb(
            resident_arena.buffer,
            output_offsets[0..width],
            output_logs[0..width],
            try wordOffset(leaf_state),
            lifting_log,
            @intCast(coefficient_cursor),
            is_final,
            0,
            leaf_seed,
        );
        gpu_ms += elapsed_leaf_gpu_ms;
        leaf_gpu_ms += elapsed_leaf_gpu_ms;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_STEPS"))
            try commitment_telemetry.logCommitStepSamples(
                resident_arena,
                group_index,
                output_offsets[0..width],
                output_logs[0..width],
                leaf_state,
            );
        previous_group_log = group_log;
        coefficient_cursor += width;
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
        std.debug.print("commit_progress tree={d} groups_done={d} coefficient_cursor={d} gpu_ms={d:.3}\n", .{
            tree_index, group_descriptors.len, coefficient_cursor, gpu_ms,
        });
    if (coefficient_cursor != coefficients.len) return Error.InvalidCardinality;
    if (use_compact_leaf_state and leaf_state_log != lifting_log) return Error.InvalidBindingSize;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_DIGESTS"))
        try commitment_telemetry.logBindingDigest(resident_arena, "commit_leaf", 0, leaf_state);
    const bottom_hashes = retained[0].size_bytes / 32;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
        std.debug.print("commit_merkle tree={d} scratch_count={d} retained_count={d} bottom_hashes={d}\n", .{
            tree_index, scratch_items.len, retained.len, bottom_hashes,
        });
        for (scratch_items, 0..) |scratch, index| std.debug.print(
            "commit_merkle_scratch tree={d} index={d} offset={d} size={d}\n",
            .{ tree_index, index, scratch.offset_bytes, scratch.size_bytes },
        );
        for (retained, 0..) |layer, index| std.debug.print(
            "commit_merkle_retained tree={d} index={d} offset={d} size={d}\n",
            .{ tree_index, index, layer.offset_bytes, layer.size_bytes },
        );
    }
    var child_offsets = std.ArrayList(u32).empty;
    defer child_offsets.deinit(allocator);
    var destination_offsets = std.ArrayList(u32).empty;
    defer destination_offsets.deinit(allocator);
    var parent_counts = std.ArrayList(u32).empty;
    defer parent_counts.deinit(allocator);
    var retained_copy_targets = std.ArrayList(?arena_plan.Binding).empty;
    defer retained_copy_targets.deinit(allocator);
    var current_offset = wordOffset(leaf_state) catch {
        std.debug.print("commit_leaf_offset_overflow tree={d} offset={d}\n", .{ tree_index, leaf_state.offset_bytes });
        return Error.InvalidBindingSize;
    };
    var current_hashes = leaf_state.size_bytes / 32;
    var ping_is_leaf = true;
    while (current_hashes > bottom_hashes) {
        const next_hashes = current_hashes / 2;
        var copy_target: ?arena_plan.Binding = null;
        const destination = if (next_hashes == bottom_hashes) blk: {
            break :blk wordOffset(retained[0]) catch {
                if (scratch_items.len == 0) return Error.MissingBinding;
                ping_is_leaf = !ping_is_leaf;
                const scratch = if (ping_is_leaf) leaf_state else scratch_items[0];
                copy_target = retained[0];
                break :blk wordOffset(scratch) catch return Error.InvalidBindingSize;
            };
        } else blk: {
            if (scratch_items.len == 0) return Error.MissingBinding;
            ping_is_leaf = !ping_is_leaf;
            const scratch = if (ping_is_leaf) leaf_state else scratch_items[0];
            break :blk wordOffset(scratch) catch {
                std.debug.print("commit_scratch_offset_overflow tree={d} offset={d}\n", .{ tree_index, scratch.offset_bytes });
                return Error.InvalidBindingSize;
            };
        };
        try child_offsets.append(allocator, current_offset);
        try destination_offsets.append(allocator, destination);
        try parent_counts.append(allocator, @intCast(next_hashes));
        try retained_copy_targets.append(allocator, copy_target);
        current_offset = destination;
        current_hashes = next_hashes;
    }
    for (retained[1..], 1..) |layer, layer_index| {
        var copy_target: ?arena_plan.Binding = null;
        const destination = wordOffset(layer) catch blk: {
            if (scratch_items.len == 0) return Error.MissingBinding;
            ping_is_leaf = !ping_is_leaf;
            const scratch = if (ping_is_leaf) leaf_state else scratch_items[0];
            if (scratch.size_bytes < layer.size_bytes) {
                std.debug.print("commit_retained_scratch_too_small tree={d} layer={d} scratch_size={d} layer_size={d}\n", .{
                    tree_index, layer_index, scratch.size_bytes, layer.size_bytes,
                });
                return Error.InvalidBindingSize;
            }
            copy_target = layer;
            break :blk wordOffset(scratch) catch return Error.InvalidBindingSize;
        };
        try child_offsets.append(allocator, current_offset);
        try destination_offsets.append(allocator, destination);
        try parent_counts.append(allocator, @intCast(layer.size_bytes / 32));
        try retained_copy_targets.append(allocator, copy_target);
        current_offset = destination;
    }
    var has_retained_copy = false;
    for (retained_copy_targets.items) |copy_target| has_retained_copy = has_retained_copy or copy_target != null;
    if (!has_retained_copy) {
        var parent_chain = try metal.prepareMerkleParentChain(
            child_offsets.items,
            destination_offsets.items,
            parent_counts.items,
            node_seed,
            cairo_domain_prefix_bytes,
        );
        defer parent_chain.deinit();
        const elapsed_parent_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
            try epoch.encodeMerkleParentChain(parent_chain);
            break :epoch_time 0;
        } else try metal.merkleParentChainPrepared(resident_arena.buffer, parent_chain);
        gpu_ms += elapsed_parent_gpu_ms;
        parent_gpu_ms += elapsed_parent_gpu_ms;
    } else {
        for (child_offsets.items, destination_offsets.items, parent_counts.items, retained_copy_targets.items) |child, destination, count, copy_target| {
            var parent_level = try metal.prepareMerkleParentChain(
                &.{child},
                &.{destination},
                &.{count},
                node_seed,
                cairo_domain_prefix_bytes,
            );
            defer parent_level.deinit();
            const elapsed_parent_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                try epoch.encodeMerkleParentChain(parent_level);
                break :epoch_time 0;
            } else try metal.merkleParentChainPrepared(resident_arena.buffer, parent_level);
            gpu_ms += elapsed_parent_gpu_ms;
            parent_gpu_ms += elapsed_parent_gpu_ms;
            if (copy_target) |target| {
                const ranges = [_]metal_runtime.ArenaCopyRange{.{
                    .source_word_offset = destination,
                    .destination_word_offset = target.offset_bytes / 4,
                    .word_count = @intCast(target.size_bytes / 4),
                }};
                var copy = try metal.prepareArenaCopies(&ranges);
                defer copy.deinit();
                const copy_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                    try epoch.encodeArenaCopy(copy);
                    break :epoch_time 0;
                } else try metal.arenaCopyPrepared(resident_arena.buffer, copy);
                gpu_ms += copy_gpu_ms;
                parent_gpu_ms += copy_gpu_ms;
            }
        }
    }
    if (command_epoch) |*epoch| {
        try epoch.submit();
        const epoch_stats = try epoch.wait();
        command_epoch_stats = epoch_stats;
        gpu_ms += epoch_stats.gpu_milliseconds;
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
        std.debug.print("commit_merkle tree={d} parents_done={d} gpu_ms={d:.3}\n", .{ tree_index, parent_counts.items.len, gpu_ms });
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_DIGESTS")) {
        for (retained, 0..) |layer, layer_index|
            try commitment_telemetry.logBindingDigest(resident_arena, "commit_retained", layer_index, layer);
    }
    const root = retained[retained.len - 1];
    const transcript_ordinals = [_]u32{ 3, 20, 23, 24 };
    const transcript_root = try oneOrdinal(schedule, plan, "TranscriptInput", transcript_ordinals[tree_index]);
    @memcpy((try resident_arena.bytes(transcript_root))[0..32], (try resident_arena.bytes(root))[0..32]);
    return .{
        .gpu_ms = gpu_ms,
        .lde_gpu_ms = lde_gpu_ms,
        .leaf_gpu_ms = leaf_gpu_ms,
        .parent_gpu_ms = parent_gpu_ms,
        .root = root,
        .command_epoch_stats = command_epoch_stats,
    };
}

fn buildProofCopies(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fri_round_count: usize,
) ![]ProofCopy {
    const transcript_ordinals = try proofCopyTranscriptOrdinals(allocator, fri_round_count);
    defer allocator.free(transcript_ordinals);
    var copies = std.ArrayList(ProofCopy).empty;
    errdefer copies.deinit(allocator);
    var cursor: u32 = 0;
    const append = struct {
        fn binding(list: *std.ArrayList(ProofCopy), alloc: std.mem.Allocator, position: *u32, source: arena_plan.Binding) !void {
            if (source.size_bytes % 4 != 0 or source.size_bytes / 4 > std.math.maxInt(u32)) return Error.InvalidBindingSize;
            const words: u32 = @intCast(source.size_bytes / 4);
            try list.append(alloc, .{ .source = source, .destination_word_offset = position.*, .word_count = words });
            position.* = std.math.add(u32, position.*, words) catch return Error.InvalidBindingSize;
        }
    }.binding;
    for (transcript_ordinals) |input| try append(
        &copies,
        allocator,
        &cursor,
        try oneOrdinal(schedule, plan, "TranscriptInput", input),
    );
    try append(&copies, allocator, &cursor, try one(schedule, plan, "DecommitAssembly"));
    return copies.toOwnedSlice(allocator);
}

fn proofCopyTranscriptOrdinals(
    allocator: std.mem.Allocator,
    fri_round_count: usize,
) ![]u32 {
    if (fri_round_count == 0 or fri_round_count > 31) return Error.InvalidCardinality;
    const ordinals = try allocator.alloc(u32, fri_round_count + 9);
    const prefix = [_]u32{ 3, 20, 23, 24, 22, 21, 25 };
    @memcpy(ordinals[0..prefix.len], &prefix);
    for (0..fri_round_count) |round| {
        ordinals[prefix.len + round] = 65536 + @as(u32, @intCast(round)) * 4;
    }
    ordinals[ordinals.len - 2] = 30;
    ordinals[ordinals.len - 1] = 31;
    return ordinals;
}

test "Cairo proof assembly uses seven runtime FRI roots" {
    const ordinals = try proofCopyTranscriptOrdinals(std.testing.allocator, 7);
    defer std.testing.allocator.free(ordinals);
    try std.testing.expectEqualSlices(u32, &.{
        3,     20,    23,    24,    22,    21,    25,
        65536, 65540, 65544, 65548, 65552, 65556, 65560,
        30,    31,
    }, ordinals);
}

test "Cairo proof assembly preserves eight-root SN2 order" {
    const ordinals = try proofCopyTranscriptOrdinals(std.testing.allocator, 8);
    defer std.testing.allocator.free(ordinals);
    try std.testing.expectEqualSlices(u32, &.{
        3,     20,    23,    24,    22,    21,    25,
        65536, 65540, 65544, 65548, 65552, 65556, 65560,
        65564, 30,    31,
    }, ordinals);
}

test "Cairo schedule-order collection accepts component-local ordinals" {
    var plan_bindings = [_]arena_plan.Binding{
        .{
            .logical_id = 40,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        },
        .{
            .logical_id = 41,
            .slot = 1,
            .offset_bytes = 16,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        },
    };
    var empty_slots: [0]arena_plan.Slot = .{};
    var empty_actions: [0]arena_plan.Action = .{};
    var empty_offsets: [0]usize = .{};
    const plan = arena_plan.Plan{
        .allocator = std.testing.allocator,
        .bindings = &plan_bindings,
        .slots = &empty_slots,
        .actions = &empty_actions,
        .action_offsets = &empty_offsets,
        .total_bytes = 32,
        .peak_live_bytes = 32,
        .plan_hash = 0,
    };
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[
        \\  {"purpose":"FixedMultiplicity","component":"range_check_8","ordinal":0,"id":41},
        \\  {"purpose":"FixedMultiplicity","component":"range_check_6","ordinal":0,"id":40}
        \\]
    ,
        .{},
    );
    defer parsed.deinit();
    const collected = try collectScheduleOrder(
        std.testing.allocator,
        parsed.value.array.items,
        plan,
        "FixedMultiplicity",
    );
    defer std.testing.allocator.free(collected);
    try std.testing.expectEqual(@as(usize, 2), collected.len);
    try std.testing.expectEqual(@as(u32, 41), collected[0].logical_id);
    try std.testing.expectEqual(@as(u32, 40), collected[1].logical_id);
}

test "Cairo relation component groups preserve instance boundaries" {
    const bindings = [_]NamedBinding{
        .{ .component = "memory_id_to_big", .ordinal = 0, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 1, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 0, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 1, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 2, .binding = undefined },
    };
    const ranges = try namedGroupRanges(std.testing.allocator, &bindings);
    defer std.testing.allocator.free(ranges);
    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try std.testing.expectEqual(NamedGroupRange{ .start = 0, .len = 2 }, ranges[0]);
    try std.testing.expectEqual(NamedGroupRange{ .start = 2, .len = 3 }, ranges[1]);

    const invalid = [_]NamedBinding{
        .{ .component = "memory_id_to_big", .ordinal = 0, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 2, .binding = undefined },
    };
    try std.testing.expectError(Error.InvalidSchedule, namedGroupRanges(std.testing.allocator, &invalid));
}

test "Cairo composition parts address global random coefficient powers" {
    var composition = try composition_bundle_mod.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();

    var saw_nonzero_component_offset = false;
    for (composition.components) |component| {
        saw_nonzero_component_offset = saw_nonzero_component_offset or component.random_coefficient_offset != 0;
        for (component.parts) |part| {
            const base = try compositionRandomCoefficientBase(
                component.random_coefficient_offset,
                part.rc_base,
            );
            try std.testing.expectEqual(component.random_coefficient_offset + part.rc_base, base);
            try std.testing.expect(base + part.program.header.n_constraints <= composition.total_constraints);
        }
    }
    try std.testing.expect(saw_nonzero_component_offset);
    try std.testing.expectError(
        Error.InvalidBindingSize,
        compositionRandomCoefficientBase(std.math.maxInt(u32), 1),
    );
}

test "Cairo composition workspace rejects inverse twiddle aliases" {
    var inverse_twiddles = arena_plan.Binding{
        .logical_id = 1,
        .slot = 1,
        .offset_bytes = 469_778_432,
        .size_bytes = 33_554_432,
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    const accumulators = arena_plan.Binding{
        .logical_id = 2,
        .slot = 2,
        .offset_bytes = 16_384,
        .size_bytes = 536_852_992,
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    try std.testing.expectError(
        Error.InvalidBindingAlias,
        validateDisjointBindings(inverse_twiddles, accumulators),
    );
    try validateDisjointActiveBindings(inverse_twiddles, accumulators);

    inverse_twiddles.occupied[0] = 1;
    var active_accumulators = accumulators;
    active_accumulators.occupied[0] = 1;
    try std.testing.expectError(
        Error.InvalidBindingAlias,
        validateDisjointActiveBindings(inverse_twiddles, active_accumulators),
    );

    inverse_twiddles.offset_bytes = accumulators.offset_bytes + accumulators.size_bytes;
    try validateDisjointBindings(inverse_twiddles, accumulators);

    inverse_twiddles.offset_bytes = std.math.maxInt(u64) - inverse_twiddles.size_bytes + 1;
    try std.testing.expectError(
        Error.InvalidBindingSize,
        validateDisjointBindings(inverse_twiddles, accumulators),
    );
}

test "Cairo component-local relation preparation rejects an empty claim layout" {
    var bindings: PreparedProofBindings = undefined;
    bindings.relation_claimed_sums = &.{};
    try std.testing.expectError(
        Error.InvalidClaimedSumCount,
        bindings.prepareRelationComponents(
            std.testing.allocator,
            undefined,
            undefined,
            &.{},
            undefined,
            undefined,
            undefined,
            undefined,
        ),
    );
}
