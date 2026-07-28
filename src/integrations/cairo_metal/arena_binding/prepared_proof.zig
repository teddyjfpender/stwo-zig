const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const composition_bundle_mod = @import("stwo_cairo_frontend").witness.composition_bundle;
const relation_bundle_mod = @import("stwo_cairo_frontend").witness.relation_bundle;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const schedule_bindings = @import("../schedule_bindings.zig");
const commitment_ordering = @import("../resident/commitment/ordering.zig");
const relation_claims = @import("../resident/relations/claims.zig");
const relation_components = @import("../resident/relations/components.zig");
const transcript_operations = @import("../resident/transcript/operations.zig");
const resident_errors = @import("../resident/errors.zig");
const resident_twiddles = @import("../resident/twiddles.zig");
const composition_recipe = @import("composition_recipe.zig");
const decommitment = @import("decommitment.zig");
const proof_assembly = @import("proof_assembly.zig");
const prepared_validation = @import("prepared_validation.zig");
const streaming_commitment = @import("streaming_commitment.zig");

const Error = resident_errors.Error;
const Sn2Counts = schedule_bindings.Sn2Counts;
const OrdinalBinding = schedule_bindings.OrdinalBinding;
const NamedBinding = schedule_bindings.NamedBinding;
const DecommitTraceGroupBindings = schedule_bindings.DecommitTraceGroupBindings;
const DecommitTraceTreeBindings = schedule_bindings.DecommitTraceTreeBindings;
const DecommitFriTreeBindings = schedule_bindings.DecommitFriTreeBindings;
const ProofDecommitGeometry = schedule_bindings.ProofDecommitGeometry;
const ProofCopy = proof_assembly.ProofCopy;
const CommitmentTelemetry = streaming_commitment.CommitmentTelemetry;
const PreparedRelationComponents = relation_components.PreparedRelationComponents;

const collectDecommitBindings = schedule_bindings.collectDecommitBindings;
const collectSn2DecommitBindings = schedule_bindings.collectSn2DecommitBindings;
const one = schedule_bindings.one;
const collect = schedule_bindings.collect;
const collectOrdinals = schedule_bindings.collectOrdinals;
const collectNamed = schedule_bindings.collectNamed;
const collectTreePurpose = commitment_ordering.collectTreePurpose;
const canonicalClaimedSumBindings = relation_claims.canonicalClaimedSumBindings;
const canonicalTraceTree = commitment_ordering.canonicalTraceTree;
const collectCommitmentOrder = commitment_ordering.collectCommitmentOrder;
const commitmentOrderCopy = commitment_ordering.commitmentOrderCopy;
const reorderTraceQueryValues = commitment_ordering.reorderTraceQueryValues;
const populateInverseTwiddles = resident_twiddles.populateInverseTwiddles;
const populateForwardTwiddleBinding = resident_twiddles.populateForwardTwiddleBinding;

const collectAssembly = proof_assembly.collectAssembly;
const buildProofCopies = proof_assembly.buildProofCopies;
const populateTraceRetainedPointers = decommitment.populateTraceRetainedPointers;
const populateFriRetainedPointers = decommitment.populateFriRetainedPointers;
const populateFriCoordinatePointers = decommitment.populateFriCoordinatePointers;
const populateSparseOffsets = decommitment.populateSparseOffsets;
const executeDecommitTraceLdeGroup = decommitment.executeTraceLdeGroup;
const prepareCompositionRecipe = composition_recipe.prepare;
const executeStreamingCommitment = streaming_commitment.execute;

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
        return prepared_validation.runtimeFriGeometry(self);
    }

    fn validate(self: PreparedProofBindings, geometry: ProofDecommitGeometry) !void {
        return prepared_validation.validate(self, geometry);
    }

    fn validateSn2(self: PreparedProofBindings) !void {
        return prepared_validation.validateSn2(self);
    }
};
