//! Complete planning-only inventory for one resident Cairo CUDA proof.
//!
//! Slot cardinalities come from the backend-neutral proof program, compact
//! protocol, and authenticated composition bundle. The shared CUDA arena owns
//! lifetime aliasing. No executable stage is implied by this plan.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const arena = @import("stwo_cuda_backend").runtime.arena;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const shared_views = @import("stwo_native_cuda_integration").common.resident_views;
const cairo_identity = @import("../identity.zig");
const quotient_topology = @import("quotient/topology.zig");
const terminal = @import("terminal_bundle.zig");
const ingress_contract = @import("resident_plan_ingress.zig");
const sizing = @import("resident_plan_sizing.zig");
const types = @import("resident_plan_types.zig");
const traceAssemblyWords = sizing.traceAssemblyWords;
const friAssemblyWords = sizing.friAssemblyWords;
const merkleWords = sizing.merkleWords;
const divCeil = sizing.divCeil;
const pow2usize = sizing.pow2usize;
const pow2 = sizing.pow2;
const words = sizing.words;
const addSize = sizing.addSize;
const mul = sizing.mul;
const add64 = sizing.add64;
const mul64 = sizing.mul64;

pub const production_ready = false;
pub const h100_80gb_bytes: u64 = 80 * 1024 * 1024 * 1024;
pub const word_bytes = types.word_bytes;
pub const SlotKind = types.SlotKind;
pub const Slot = types.Slot;
pub const Summary = types.Summary;
pub const QuotientGeometry = types.QuotientGeometry;
pub const Error = types.Error;
pub const IngressGeometry = ingress_contract.Geometry;

/// Execution work which remains after this structural memory contract.
pub const architecture_gaps = [_][]const u8{
    "mixed-height trace commitment and Merkle stage hooks",
    "constraint/relation output binding into composition coefficients",
    "Cairo OODS and quotient descriptor lowering",
    "FRI fold/commit hooks over the dynamic layer inventory",
    "proof-session PoW and decommitment hooks",
    "authenticated compact terminal serialization from full decommitment assembly",
    "identity-checked process cache materialization for fixed columns",
};

pub const Plan = struct {
    slots: []Slot,
    requirements: []arena.Requirement,
    request_arena: arena.Plan,
    terminal_bundle: terminal.Bundle,
    program_identity: proof_ir.Digest,
    protocol_identity: proof_ir.Digest,
    ingress_identity: proof_ir.Digest,
    quotient_geometry: QuotientGeometry,
    identity: proof_ir.Digest,
    summary: Summary,

    pub fn init(
        allocator: std.mem.Allocator,
        program: proof_ir.ProofProgram,
        protocol: compact.CompactProtocolV1,
        bundle: composition.Bundle,
        ingress: IngressGeometry,
    ) !Plan {
        try validateInputs(program, protocol, bundle, ingress);
        ingress.validate() catch return Error.InvalidIngressGeometry;
        var quotient = try quotient_topology.derive(
            allocator,
            bundle,
            program,
            protocol,
        );
        defer quotient.deinit();
        var output = Builder{
            .allocator = allocator,
            .program = program,
            .protocol = protocol,
            .bundle = bundle,
            .quotient = &quotient,
            .ingress = ingress,
        };
        defer output.slots.deinit(allocator);
        try output.addIngress();
        try output.addTraceTrees();
        try output.addConstraint();
        try output.addOods();
        try output.addQuotient();
        try output.addFri();
        try output.addPow();
        const decommit_words = try output.addDecommit();

        var proof = try terminal.Bundle.init(
            allocator,
            .{ .protocol = protocol },
            .{ .capacity_words = protocol.decommitment_capacity_words },
        );
        errdefer proof.deinit(allocator);
        try proof.validate(protocol.decommitment_capacity_words);
        try output.add(
            .terminal_bundle,
            0,
            proof.total_words,
            64,
            .proof_assembly,
            .proof_assembly,
            .request_local,
            false,
        );

        const slots = try output.slots.toOwnedSlice(allocator);
        errdefer allocator.free(slots);
        const requirements = try requestRequirements(allocator, slots);
        errdefer allocator.free(requirements);
        var request_arena = try arena.Plan.init(allocator, requirements);
        errdefer request_arena.deinit(allocator);
        const summary = try summarize(
            slots,
            request_arena.total_words,
            output.coefficient_cells,
            output.evaluation_cells,
            proof.total_words,
            decommit_words,
            protocol.decommitment_capacity_words,
        );
        return .{
            .slots = slots,
            .requirements = requirements,
            .request_arena = request_arena,
            .terminal_bundle = proof,
            .program_identity = program.program_digest,
            .protocol_identity = try cairo_identity.protocolDigest(
                protocol,
            ),
            .ingress_identity = try ingress.identity(),
            .quotient_geometry = try quotientGeometry(quotient),
            .identity = planIdentity(
                program,
                protocol,
                bundle.plan_hash,
                try ingress.identity(),
                quotient.identity,
                slots,
                summary,
            ),
            .summary = summary,
        };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        self.request_arena.deinit(allocator);
        allocator.free(self.requirements);
        allocator.free(self.slots);
        self.terminal_bundle.deinit(allocator);
        self.* = undefined;
    }

    pub fn slot(self: Plan, kind: SlotKind, ordinal: u32) ?Slot {
        for (self.slots) |candidate| {
            if (candidate.kind == kind and candidate.ordinal == ordinal)
                return candidate;
        }
        return null;
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bundle: composition.Bundle,
    quotient: *const quotient_topology.Topology,
    ingress: IngressGeometry,
    slots: std.ArrayList(Slot) = .empty,
    coefficient_cells: u64 = 0,
    evaluation_cells: u64 = 0,

    fn addIngress(self: *Builder) !void {
        const writer = self.ingress.writer;
        const relation = self.ingress.relation;
        const evaluation = self.ingress.evaluation;
        try self.add(.adapted_input, 0, try words(self.ingress.adapted_input_words), 64, .ingress, .trace_generation, .request_local, true);
        try self.add(.statement_bootstrap, 0, try words(self.ingress.statement_bootstrap_words), 4, .ingress, .trace_commit, .request_local, true);
        try self.add(.writer_inputs, 0, try words(writer.input_words), 64, .ingress, .trace_generation, .request_local, false);
        try self.add(.writer_pointer_tables, 0, try words(writer.pointer_words), 2, .ingress, .trace_generation, .request_local, false);
        try self.add(.writer_descriptors, 0, try words(writer.descriptor_words), 8, .ingress, .trace_generation, .request_local, true);
        try self.add(.writer_lookup_inputs, 0, try words(writer.lookup_words), 64, .trace_generation, .trace_commit, .request_local, false);
        try self.add(.writer_scratch, 0, try words(writer.scratch_words), 64, .trace_generation, .trace_generation, .request_local, false);
        try self.add(.fixed_writer_tables, 0, try words(writer.fixed_table_words), 2, .ingress, .trace_generation, .request_local, false);
        try self.add(.memory_writer_tables, 0, try words(writer.memory_table_words), 2, .ingress, .trace_generation, .request_local, false);

        try self.add(.relation_top_level_tables, 0, try words(relation.top_level_pointer_words), 2, .ingress, .trace_commit, .request_local, false);
        try self.add(.relation_source_pointer_tables, 0, try words(relation.source_pointer_words), 2, .ingress, .trace_commit, .request_local, false);
        try self.add(.relation_descriptors, 0, try words(relation.descriptor_words), 4, .ingress, .trace_commit, .request_local, true);
        try self.add(.relation_geometry, 0, try words(relation.geometry_words), 4, .ingress, .trace_commit, .request_local, true);
        try self.add(.relation_challenges, 0, try words(relation.challenge_words), 4, .trace_commit, .constraint_evaluation, .request_local, false);
        try self.add(.relation_z, 0, 4, 4, .trace_commit, .constraint_evaluation, .request_local, false);
        try self.add(.relation_alpha_powers, 0, try words(relation.alpha_power_words), 4, .trace_commit, .constraint_evaluation, .request_local, false);
        try self.add(.relation_denominators, 0, try words(relation.denominator_words), 4, .trace_commit, .trace_commit, .request_local, false);
        try self.add(.relation_claimed_sums, 0, try words(relation.claimed_sum_words), 4, .trace_commit, .proof_assembly, .request_local, false);
        try self.add(.relation_output_graph, 0, try words(relation.output_pointer_words), 2, .ingress, .trace_commit, .request_local, false);
        try self.add(.relation_reduction_scratch, 0, try words(relation.reduction_scratch_words), 64, .trace_commit, .trace_commit, .request_local, false);
        try self.add(.relation_scan_scratch, 0, try words(relation.scan_scratch_words), 64, .trace_commit, .trace_commit, .request_local, false);

        try self.add(.eval_arguments, 0, try words(evaluation.argument_words), 2, .ingress, .constraint_evaluation, .request_local, false);
        try self.add(.eval_trace_offsets, 0, try words(evaluation.trace_offset_words), 2, .ingress, .constraint_evaluation, .request_local, true);
        try self.add(.eval_interaction_offsets, 0, try words(evaluation.interaction_offset_words), 2, .ingress, .constraint_evaluation, .request_local, true);
        try self.add(.eval_lde_descriptors, 0, try words(evaluation.lde_descriptor_words), 2, .ingress, .constraint_evaluation, .request_local, true);
        try self.add(.eval_lde_tile, 0, try words(evaluation.lde_tile_words), 64, .constraint_evaluation, .constraint_evaluation, .request_local, false);
        if (evaluation.base_parameter_words != 0) {
            try self.add(.eval_base_parameters, 0, try words(evaluation.base_parameter_words), 4, .trace_commit, .constraint_evaluation, .request_local, false);
        }
        try self.add(.eval_extended_parameter_descriptors, 0, try words(evaluation.extended_parameter_descriptor_words), 4, .ingress, .constraint_evaluation, .request_local, true);
        try self.add(.eval_extended_parameters, 0, try words(evaluation.extended_parameter_words), 4, .trace_commit, .constraint_evaluation, .request_local, false);
        try self.add(.eval_composition_offsets, 0, try words(evaluation.composition_offset_words), 2, .ingress, .constraint_evaluation, .request_local, true);
        try self.add(.constraint_composition_accumulator, 0, try words(evaluation.composition_accumulator_words), 64, .constraint_evaluation, .constraint_evaluation, .request_local, false);
    }

    fn addTraceTrees(self: *Builder) !void {
        var max_commitment_log: u32 = 0;
        var trace_progressive_log: u32 = 0;
        var constraint_progressive_log: u32 = 0;
        for (self.program.commitments) |tree| {
            max_commitment_log = @max(
                max_commitment_log,
                tree.evaluation_log_rows,
            );
            if (!treeIsMixed(self.program, tree)) continue;
            switch (commitStageFor(tree.role)) {
                .trace_commit => trace_progressive_log = @max(
                    trace_progressive_log,
                    tree.evaluation_log_rows,
                ),
                .constraint_evaluation => constraint_progressive_log = @max(
                    constraint_progressive_log,
                    tree.evaluation_log_rows,
                ),
                else => return Error.UnsupportedGeometry,
            }
        }
        if (max_commitment_log < 2) return Error.UnsupportedGeometry;
        const twiddle_words = try pow2usize(max_commitment_log - 1);
        try self.add(.twiddles_forward, 0, twiddle_words, 64, .ingress, .fri_commit, .process_cache, true);
        try self.add(.twiddles_inverse, 0, twiddle_words, 64, .ingress, .fri_commit, .process_cache, true);
        if (trace_progressive_log != 0) {
            try self.add(
                .trace_progressive_states,
                0,
                try mul(
                    try pow2usize(trace_progressive_log),
                    progressive_state_words,
                ),
                64,
                .trace_commit,
                .trace_commit,
                .request_local,
                false,
            );
        }
        if (constraint_progressive_log != 0) {
            try self.add(
                .trace_progressive_states,
                1,
                try mul(
                    try pow2usize(constraint_progressive_log),
                    progressive_state_words,
                ),
                64,
                .constraint_evaluation,
                .constraint_evaluation,
                .request_local,
                false,
            );
        }
        for (self.program.commitments, 0..) |tree, ordinal| {
            const columns = self.program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
            var coefficients: u64 = 0;
            for (columns) |column| {
                coefficients = try add64(coefficients, try pow2(column.log_rows));
            }
            const evaluations = try mul64(
                coefficients,
                try pow2(self.protocol.log_blowup_factor),
            );
            if (tree.role == .interaction and
                coefficients != self.ingress.relation.output_coordinate_words)
            {
                return Error.InvalidIngressGeometry;
            }
            self.coefficient_cells = try add64(self.coefficient_cells, coefficients);
            self.evaluation_cells = try add64(self.evaluation_cells, evaluations);
            const storage: proof_ir.StorageClass =
                if (tree.role == .preprocessed) .process_cache else .request_local;
            const first = firstFor(tree.role);
            const coefficient_last: telemetry.Stage =
                if (tree.role == .composition) .decommit else .oods;
            try self.add(
                if (tree.role == .composition)
                    .constraint_composition_output
                else
                    .trace_coefficients,
                @intCast(ordinal),
                try words(coefficients),
                64,
                first,
                coefficient_last,
                storage,
                tree.role == .preprocessed,
            );
            try self.add(.trace_evaluations, @intCast(ordinal), try words(evaluations), 64, first, .decommit, storage, tree.role == .preprocessed);
            try self.add(.trace_column_logs, @intCast(ordinal), columns.len, 1, first, .decommit, storage, true);
            try self.add(.trace_column_offsets, @intCast(ordinal), columns.len + 1, 1, first, .decommit, storage, true);
            try self.add(.trace_merkle_hashes, @intCast(ordinal), try merkleWords(tree.evaluation_log_rows), 64, .trace_commit, .decommit, storage, tree.role == .preprocessed);
            try self.add(.trace_merkle_layers, @intCast(ordinal), (@as(usize, tree.evaluation_log_rows) + 1) * 4, 4, .trace_commit, .decommit, storage, true);
            try self.add(.trace_root, @intCast(ordinal), 8, 8, .trace_commit, .proof_assembly, .request_local, false);
        }
    }

    fn addConstraint(self: *Builder) !void {
        var denominators: usize = 0;
        for (self.bundle.components) |component| {
            denominators = try addSize(
                denominators,
                component.denominator_inverses.len,
            );
        }
        try self.add(.transcript, 0, 64, 8, .ingress, .proof_assembly, .request_local, false);
        try self.add(.interaction_claims, 0, try mul(self.protocol.interaction_sum_count, 4), 4, .constraint_evaluation, .proof_assembly, .request_local, false);
        try self.add(.composition_alpha, 0, 4, 4, .trace_commit, .constraint_evaluation, .request_local, false);
        try self.add(.constraint_random_powers, 0, try mul(self.program.quotient.term_count, 4), 4, .constraint_evaluation, .quotient, .request_local, false);
        try self.add(.constraint_denominators, 0, denominators, 4, .ingress, .quotient, .request_local, true);
    }

    fn addOods(self: *Builder) !void {
        const samples = self.protocol.sampled_value_words / 4;
        const max_log = self.program.quotient.evaluation_log_rows;
        const factors = try mul(try mul(samples, max_log), 4);
        const first_blocks = divCeil(try pow2usize(max_log), 4096);
        const reduce_blocks = divCeil(try pow2usize(max_log), 512);
        try self.add(.oods_parameter, 0, 4, 4, .oods, .quotient, .request_local, false);
        try self.add(.oods_offset_points, 0, try mul(samples, 2), 2, .oods, .oods, .request_local, false);
        try self.add(.oods_fold_counts, 0, samples, 1, .oods, .oods, .request_local, false);
        try self.add(.oods_output_indices, 0, samples, 1, .oods, .oods, .request_local, false);
        try self.add(.oods_sample_points, 0, try mul(samples, 8), 8, .oods, .quotient, .request_local, false);
        try self.add(.oods_evaluation_points, 0, try mul(samples, 8), 8, .oods, .quotient, .request_local, false);
        try self.add(.oods_folding_factors, 0, factors, 4, .oods, .oods, .request_local, false);
        try self.add(.oods_reduce_a, 0, try mul(try mul(samples, first_blocks), 4), 4, .oods, .oods, .request_local, false);
        try self.add(.oods_reduce_b, 0, try mul(try mul(samples, reduce_blocks), 4), 4, .oods, .oods, .request_local, false);
        try self.add(.oods_sampled_values, 0, self.protocol.sampled_value_words, 4, .oods, .proof_assembly, .request_local, false);
    }

    fn addQuotient(self: *Builder) !void {
        const terms = self.quotient.prepared_terms.len;
        const groups = self.quotient.group_log_sizes.len;
        const sources = self.quotient.sources.len;
        const partial_rows = self.quotient.partial_offsets[groups];
        try self.add(.quotient_challenge, 0, 4, 4, .quotient, .fri_commit, .request_local, false);
        try self.add(.quotient_prepared_terms, 0, try mul(terms, 5), 4, .quotient, .quotient, .request_local, true);
        try self.add(.quotient_group_offsets, 0, @as(usize, groups) + 1, 1, .quotient, .quotient, .request_local, true);
        try self.add(.quotient_group_term_indices, 0, terms, 1, .quotient, .quotient, .request_local, true);
        try self.add(.quotient_batch_terms, 0, try mul(terms, 3), 1, .quotient, .quotient, .request_local, true);
        try self.add(
            .quotient_source_descriptors,
            0,
            try mul(sources, 4),
            2,
            .ingress,
            .quotient,
            .request_local,
            true,
        );
        try self.add(.quotient_group_logs, 0, groups, 1, .quotient, .quotient, .request_local, true);
        try self.add(.quotient_partial_logs, 0, groups, 1, .quotient, .quotient, .request_local, true);
        try self.add(
            .quotient_partial_offsets,
            0,
            try mul(@as(usize, groups) + 1, 2),
            2,
            .ingress,
            .quotient,
            .request_local,
            true,
        );
        try self.add(.quotient_term_points, 0, try mul(terms, 8), 8, .quotient, .quotient, .request_local, false);
        try self.add(.quotient_line_coefficients, 0, try mul(terms, 12), 4, .quotient, .quotient, .request_local, false);
        try self.add(.quotient_group_points, 0, try mul(groups, 8), 8, .quotient, .quotient, .request_local, false);
        try self.add(.quotient_first_linear_terms, 0, try mul(groups, 4), 4, .quotient, .quotient, .request_local, false);
        try self.add(.quotient_partial_coordinates, 0, try words(try mul64(partial_rows, 4)), 64, .quotient, .quotient, .request_local, false);
        try self.add(.quotient_result_coordinates, 0, try mul(try pow2usize(self.program.quotient.evaluation_log_rows), 4), 64, .quotient, .fri_commit, .request_local, false);
    }

    fn addFri(self: *Builder) !void {
        try self.add(.fri_alpha, 0, 4, 4, .fri_commit, .fri_commit, .request_local, false);
        for (self.program.fri_layers, 0..) |layer, ordinal| {
            if (ordinal != 0) try self.add(
                .fri_coordinates,
                @intCast(ordinal),
                try mul(try pow2usize(layer.evaluation_log_rows), 4),
                64,
                .fri_commit,
                .decommit,
                .request_local,
                false,
            );
            try self.add(.fri_merkle_hashes, @intCast(ordinal), try merkleWords(layer.evaluation_log_rows), 64, .fri_commit, .decommit, .request_local, false);
            try self.add(.fri_merkle_layers, @intCast(ordinal), (@as(usize, layer.evaluation_log_rows) + 1) * 4, 4, .fri_commit, .decommit, .request_local, true);
        }
        const last_layer = self.program.fri_layers[
            self.program.fri_layers.len - 1
        ];
        if (last_layer.fold_step > last_layer.evaluation_log_rows)
            return Error.UnsupportedGeometry;
        const terminal_words = try mul(
            try pow2usize(
                last_layer.evaluation_log_rows - last_layer.fold_step,
            ),
            4,
        );
        const transcript_words = try mul(
            self.protocol.final_line_coefficient_count,
            4,
        );
        try self.add(.fri_last_evaluation, 0, terminal_words, 4, .fri_commit, .fri_commit, .request_local, false);
        try self.add(.fri_last_coefficients, 0, terminal_words, 4, .fri_commit, .proof_assembly, .request_local, false);
        try self.add(.fri_last_degree_error, 0, 1, 1, .fri_commit, .proof_assembly, .request_local, false);
        try self.add(.fri_last_transcript, 0, transcript_words, 4, .fri_commit, .proof_assembly, .request_local, false);
    }

    fn addPow(self: *Builder) !void {
        inline for (.{ telemetry.Stage.trace_commit, telemetry.Stage.pow }, 0..) |stage, ordinal| {
            try self.add(.pow_prefix, ordinal, 8, 8, stage, stage, .request_local, false);
            try self.add(.pow_best_nonce, ordinal, 2, 2, stage, stage, .request_local, false);
            try self.add(.pow_completed_blocks, ordinal, 1, 1, stage, stage, .request_local, false);
            try self.add(.pow_transcript_nonce, ordinal, 2, 2, stage, .proof_assembly, .request_local, false);
        }
    }

    fn addDecommit(self: *Builder) !usize {
        const queries: usize = self.protocol.query_count;
        var max_expanded = queries;
        var assembly = try addSize(
            try addSize(
                8,
                try mul(self.protocol.decommitment_record_count, 16),
            ),
            try mul(queries, 2),
        );
        var max_log: u32 = 0;
        var column_count: usize = 0;
        for (self.program.commitments) |tree| {
            max_log = @max(max_log, tree.evaluation_log_rows);
            column_count = try addSize(column_count, tree.column_count);
            assembly = try addSize(
                assembly,
                try traceAssemblyWords(
                    queries,
                    tree.column_count,
                    tree.evaluation_log_rows,
                ),
            );
        }
        for (self.program.fri_layers) |layer| {
            max_log = @max(max_log, layer.evaluation_log_rows);
            const expanded = try mul(queries, try pow2usize(layer.fold_step));
            max_expanded = @max(max_expanded, expanded);
            if (layer.log_rows_per_leaf > layer.evaluation_log_rows)
                return Error.UnsupportedGeometry;
            assembly = try addSize(
                assembly,
                try friAssemblyWords(
                    queries,
                    expanded,
                    layer.evaluation_log_rows - layer.log_rows_per_leaf,
                ),
            );
        }
        try self.add(.decommit_raw_queries, 0, queries, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_unique_queries, 0, queries, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_mapped_queries, 0, queries, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_walk_queries, 0, max_expanded, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_walk_scratch, 0, max_expanded, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_leaf_indices, 0, 1, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_expanded_positions, 0, max_expanded, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_sparse_indices, 0, 1, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_sparse_hashes, 0, 8, 8, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_counts, 0, 5, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_level_offsets, 0, @as(usize, max_log) + 1, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_level_counts, 0, @as(usize, max_log) + 1, 1, .decommit, .decommit, .request_local, false);
        try self.add(.decommit_column_logs, 0, column_count, 1, .decommit, .decommit, .request_local, true);
        try self.add(
            .decommit_assembly,
            0,
            self.protocol.decommitment_capacity_words,
            64,
            .decommit,
            .proof_assembly,
            .request_local,
            false,
        );
        return assembly;
    }

    fn add(
        self: *Builder,
        kind: SlotKind,
        ordinal: u32,
        slot_words: usize,
        alignment: usize,
        live_from: telemetry.Stage,
        live_through: telemetry.Stage,
        storage: proof_ir.StorageClass,
        immutable: bool,
    ) !void {
        if (slot_words == 0 or alignment == 0 or
            !std.math.isPowerOfTwo(alignment) or
            live_from.index() > live_through.index())
        {
            return Error.UnsupportedGeometry;
        }
        const id = std.math.cast(u32, self.slots.items.len + 1) orelse
            return Error.GeometryOverflow;
        try self.slots.append(self.allocator, .{
            .id = id,
            .kind = kind,
            .ordinal = ordinal,
            .words = slot_words,
            .alignment_words = alignment,
            .live_from = live_from,
            .live_through = live_through,
            .storage = storage,
            .immutable = immutable,
            .identity = slotIdentity(
                self.program,
                self.bundle.plan_hash,
                kind,
                ordinal,
                slot_words,
                alignment,
                live_from,
                live_through,
                storage,
                immutable,
            ),
        });
    }
};

fn validateInputs(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    bundle: composition.Bundle,
    ingress: IngressGeometry,
) !void {
    program.validate() catch return Error.InvalidProgram;
    protocol.validate() catch return Error.UnsupportedGeometry;
    if (program.identity.frontend != .cairo or
        program.commitments.len != 4 or
        program.constraints.len != bundle.components.len or
        program.quotient.term_count != bundle.total_constraints or
        program.quotient.group_count != bundle.components.len or
        program.fri_layers.len != protocol.fri_tree_count or
        bundle.plan_hash == 0)
    {
        return Error.InvalidComposition;
    }
    const roles = [_]proof_ir.CommitmentRole{
        .preprocessed,
        .main,
        .interaction,
        .composition,
    };
    var next_column: u32 = 0;
    for (program.commitments, roles, protocol.trace_columns) |tree, role, count| {
        if (tree.role != role or tree.first_column != next_column or
            tree.column_count != count)
        {
            return Error.UnsupportedGeometry;
        }
        const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
        var expected_log: u32 = 0;
        for (columns) |column| {
            if (@intFromEnum(column.role) != @intFromEnum(role))
                return Error.UnsupportedGeometry;
            expected_log = @max(
                expected_log,
                std.math.add(
                    u32,
                    column.log_rows,
                    protocol.log_blowup_factor,
                ) catch return Error.GeometryOverflow,
            );
        }
        if (tree.evaluation_log_rows != expected_log)
            return Error.UnsupportedGeometry;
        next_column = std.math.add(u32, next_column, count) catch
            return Error.GeometryOverflow;
    }
    if (next_column != program.trace_columns.len)
        return Error.UnsupportedGeometry;
    for (bundle.components, program.constraints) |component, constraint| {
        if (constraint.constraint_count != component.n_constraints or
            constraint.max_degree_log !=
                component.evaluation_log_size - component.trace_log_size)
        {
            return Error.InvalidComposition;
        }
    }
    ingress_contract.validateEvaluation(
        bundle,
        ingress.evaluation,
    ) catch return Error.InvalidIngressGeometry;
    // Reference the shared resident ABI at compile time. Cairo owns dynamic
    // cardinalities only; typed stage views remain the native common contract.
    _ = shared_views.TraceTrees;
    _ = shared_views.Oods;
    _ = shared_views.Quotient;
    _ = shared_views.Fri;
    _ = shared_views.Pow;
    _ = shared_views.Decommit;
}

fn requestRequirements(
    allocator: std.mem.Allocator,
    slots: []const Slot,
) ![]arena.Requirement {
    var count: usize = 0;
    for (slots) |slot| if (slot.storage == .request_local) {
        count += 1;
    };
    if (count == 0) return Error.UnsupportedGeometry;
    const requirements = try allocator.alloc(arena.Requirement, count);
    var cursor: usize = 0;
    for (slots) |slot| {
        if (slot.storage != .request_local) continue;
        requirements[cursor] = .{
            .id = slot.id,
            .words = slot.words,
            .alignment_words = slot.alignment_words,
            .live_from = slot.live_from,
            .live_through = slot.live_through,
        };
        cursor += 1;
    }
    return requirements;
}

fn summarize(
    slots: []const Slot,
    arena_words: usize,
    coefficient_cells: u64,
    evaluation_cells: u64,
    proof_words: usize,
    decommit_words: usize,
    terminal_decommit_words: usize,
) !Summary {
    var logical: u64 = 0;
    var request: u64 = 0;
    var persistent: u64 = 0;
    for (slots) |slot| {
        logical = try add64(logical, slot.words);
        if (slot.storage == .request_local) {
            request = try add64(request, slot.words);
        } else {
            persistent = try add64(persistent, slot.words);
        }
    }
    var peak: u64 = 0;
    inline for (std.meta.fields(telemetry.Stage)) |field| {
        const stage: telemetry.Stage = @enumFromInt(field.value);
        var live: u64 = 0;
        for (slots) |slot| {
            if (slot.live_from.index() <= stage.index() and
                slot.live_through.index() >= stage.index())
            {
                live = try add64(live, slot.words);
            }
        }
        peak = @max(peak, live);
    }
    return .{
        .slot_count = slots.len,
        .logical_words = logical,
        .request_logical_words = request,
        .persistent_words = persistent,
        .request_arena_words = arena_words,
        .peak_live_words = peak,
        .allocated_resident_words = try add64(arena_words, persistent),
        .coefficient_cells = coefficient_cells,
        .evaluation_cells = evaluation_cells,
        .terminal_words = proof_words,
        .decommit_assembly_words = decommit_words,
        .decommit_terminal_shortfall_words = if (decommit_words > terminal_decommit_words)
            decommit_words - terminal_decommit_words
        else
            0,
    };
}

fn firstFor(role: proof_ir.CommitmentRole) telemetry.Stage {
    return switch (role) {
        .preprocessed => .ingress,
        .main => .trace_generation,
        .interaction => .trace_commit,
        .composition => .constraint_evaluation,
        .fri => unreachable,
    };
}

const progressive_state_words: usize = 24;

fn commitStageFor(role: proof_ir.CommitmentRole) telemetry.Stage {
    return switch (role) {
        .preprocessed, .main, .interaction => .trace_commit,
        .composition => .constraint_evaluation,
        .fri => unreachable,
    };
}

fn treeIsMixed(
    program: proof_ir.ProofProgram,
    tree: proof_ir.CommitmentTree,
) bool {
    const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
    if (columns.len < 2) return false;
    const first_log = columns[0].log_rows;
    for (columns[1..]) |column| {
        if (column.log_rows != first_log) return true;
    }
    return false;
}

fn slotIdentity(
    program: proof_ir.ProofProgram,
    plan_hash: u64,
    kind: SlotKind,
    ordinal: u32,
    slot_words: usize,
    alignment: usize,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
    storage: proof_ir.StorageClass,
    immutable: bool,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-cairo-cuda-resident-slot-v2");
    hash.update(&program.semantic_digest);
    hashInt(&hash, u64, plan_hash);
    hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u32, ordinal);
    hashInt(&hash, u64, slot_words);
    hashInt(&hash, u64, alignment);
    hashInt(&hash, u8, @intFromEnum(live_from));
    hashInt(&hash, u8, @intFromEnum(live_through));
    hashInt(&hash, u8, @intFromEnum(storage));
    hashInt(&hash, u8, @intFromBool(immutable));
    var result: proof_ir.Digest = undefined;
    hash.final(&result);
    return result;
}

fn planIdentity(
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
    composition_plan_hash: u64,
    ingress_identity: proof_ir.Digest,
    quotient_identity: proof_ir.Digest,
    slots: []const Slot,
    summary: Summary,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig-cairo-cuda-resident-plan-v2");
    hash.update(&program.program_digest);
    hash.update(&(protocol.encode() catch unreachable));
    hashInt(&hash, u64, composition_plan_hash);
    hash.update(&ingress_identity);
    hash.update(&quotient_identity);
    for (slots) |slot| hash.update(&slot.identity);
    hashInt(&hash, u64, summary.logical_words);
    hashInt(&hash, u64, summary.request_arena_words);
    hashInt(&hash, u64, summary.persistent_words);
    var result: proof_ir.Digest = undefined;
    hash.final(&result);
    return result;
}

fn quotientGeometry(
    topology: quotient_topology.Topology,
) Error!QuotientGeometry {
    return .{
        .term_count = topology.prepared_terms.len,
        .group_count = topology.group_log_sizes.len,
        .source_count = topology.sources.len,
        .partial_word_count = std.math.cast(
            usize,
            topology.partial_offsets[topology.partial_offsets.len - 1],
        ) orelse return Error.GeometryOverflow,
        .maximum_partial_rows = topology.maximum_partial_rows,
        .identity = topology.identity,
    };
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
