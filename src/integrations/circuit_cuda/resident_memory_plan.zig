//! Exact slot inventory for one circuit-recursion CUDA proof. The shared
//! arena assigns offsets from these inclusive protocol lifetimes; a slot
//! cannot be recycled while its commitment or opening still needs it.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const arena = cuda.runtime.arena;
const Stage = cuda.runtime.telemetry.Stage;
const field = cuda.abi.field;
const commit = @import("resident_commit.zig");
const interaction = @import("resident_interaction.zig");
const composition = @import("resident_composition.zig");
const oods = @import("resident_oods.zig");
const quotient = @import("resident_quotient.zig");
const fri = @import("resident_fri.zig");
const decommit = @import("resident_decommit.zig");
const terminal = @import("resident_terminal_bundle.zig");

pub const Kind = enum(u8) {
    values,
    preprocessed_source,
    base_source,
    interaction_source,
    commit_coefficients,
    commit_evaluations,
    commit_logs,
    commit_hashes,
    commit_layers,
    twiddles_forward,
    twiddles_inverse,
    transcript_state,
    transcript_boundary,
    transcript_salt,
    transcript_config,
    transcript_lookup,
    pow_prefix,
    pow_best,
    pow_completed,
    pow_nonce,
    interaction_drawn,
    interaction_powers,
    interaction_z,
    interaction_denominator,
    interaction_claims,
    interaction_pointer_table,
    interaction_output_tables,
    interaction_denominator_tables,
    interaction_claim_tables,
    interaction_geometry,
    interaction_reduce,
    interaction_scan,
    circuit_hash,
    error_flag,
    composition_constants,
    composition_arguments,
    composition_trace_offsets,
    composition_interaction_offsets,
    composition_lde_descriptors,
    composition_ext_descriptors,
    composition_ext_values,
    composition_denominators,
    composition_lde_tile,
    composition_accumulators,
    composition_powers,
    composition_alpha,
    oods_parameter,
    oods_offsets,
    oods_folds,
    oods_indices,
    oods_sample_points,
    oods_evaluation_points,
    oods_factors,
    oods_reduce_a,
    oods_reduce_b,
    oods_values,
    quotient_challenge,
    quotient_terms,
    quotient_group_offsets,
    quotient_group_term_indices,
    quotient_batch_terms,
    quotient_sources,
    quotient_group_logs,
    quotient_partial_logs,
    quotient_partial_offsets,
    quotient_term_points,
    quotient_lines,
    quotient_group_points,
    quotient_first_terms,
    quotient_partial_coordinates,
    quotient_result,
    quotient_subdomain,
    quotient_inverse_twiddles,
    quotient_coefficient_logs,
    fri_alpha,
    fri_coordinates,
    fri_hashes,
    fri_layers,
    fri_last_evaluation,
    fri_last_coefficients,
    fri_degree_error,
    fri_last_transcript,
    decommit_raw,
    decommit_unique,
    decommit_mapped,
    decommit_walk,
    decommit_walk_scratch,
    decommit_leaf_indices,
    decommit_expanded,
    decommit_sparse_indices,
    decommit_sparse_hashes,
    decommit_counts,
    decommit_level_offsets,
    decommit_level_counts,
    decommit_column_logs,
    terminal_bundle,
};

pub const Slot = struct {
    kind: Kind,
    ordinal: u16,
    requirement: arena.Requirement,
};

pub const Input = struct {
    value_count: usize,
    twiddle_words: usize,
    retain_static: bool = false,
    commitments: *const [4]commit.Plan,
    interaction: *const interaction.Plan,
    composition: *const composition.Plan,
    oods: *const oods.Plan,
    quotient: *const quotient.Topology,
    fri: *const fri.Plan,
    decommit: *const decommit.Plan,
    terminal: *const terminal.Bundle,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    slots: []Slot,
    requirements: []arena.Requirement,
    placement: arena.Plan,

    pub fn init(allocator: std.mem.Allocator, input: Input) !Plan {
        var builder = Builder{ .allocator = allocator };
        defer builder.slots.deinit(allocator);
        try builder.build(input);
        const slots = try builder.slots.toOwnedSlice(allocator);
        errdefer allocator.free(slots);
        const requirements = try allocator.alloc(arena.Requirement, slots.len);
        errdefer allocator.free(requirements);
        for (slots, requirements) |entry, *requirement| requirement.* = entry.requirement;
        const placement = try arena.Plan.init(allocator, requirements);
        return .{ .allocator = allocator, .slots = slots, .requirements = requirements, .placement = placement };
    }

    pub fn deinit(self: *Plan) void {
        self.placement.deinit(self.allocator);
        self.allocator.free(self.requirements);
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn slot(self: *const Plan, kind: Kind, ordinal: u16) !Slot {
        for (self.slots) |entry| if (entry.kind == kind and entry.ordinal == ordinal) return entry;
        return error.MissingCircuitResidentSlot;
    }

    pub fn bytes(self: *const Plan) !usize {
        return mul(self.placement.total_words, 4);
    }

    /// Only an identical physical layout may borrow a process-owned arena.
    /// Hash every slot's extent, offset, alignment and stage lifetime so a
    /// different fold geometry cannot reuse stale device addresses.
    pub fn cacheKey(self: *const Plan) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/circuit-cuda-arena/v1\x00");
        hashInt(u64, &hash, @intCast(self.placement.total_words));
        hashInt(u64, &hash, @intCast(self.placement.placements.len));
        for (self.placement.placements) |placement| {
            const requirement = placement.requirement;
            hashInt(u32, &hash, requirement.id);
            hashInt(u64, &hash, @intCast(requirement.words));
            hashInt(u64, &hash, @intCast(requirement.alignment_words));
            hashInt(u8, &hash, @intFromEnum(requirement.live_from));
            hashInt(u8, &hash, @intFromEnum(requirement.live_through));
            hashInt(u8, &hash, requirement.live_from_phase);
            hashInt(u8, &hash, requirement.live_through_phase);
            hashInt(u64, &hash, @intCast(placement.offset_words));
        }
        return hash.finalResult();
    }
};

fn hashInt(comptime T: type, hash: *std.crypto.hash.sha2.Sha256, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

const Builder = struct {
    allocator: std.mem.Allocator,
    slots: std.ArrayList(Slot) = .empty,

    fn add(self: *Builder, kind: Kind, ordinal: usize, words: usize, alignment: usize, from: Stage, through: Stage) !void {
        if (words == 0 or ordinal >= 256) return error.InvalidCircuitResidentSlot;
        const index = @intFromEnum(kind);
        const id = try addSize(try mul(index, 256), ordinal);
        try self.slots.append(self.allocator, .{
            .kind = kind,
            .ordinal = @intCast(ordinal),
            .requirement = .{
                .id = @intCast(id),
                .words = words,
                .alignment_words = alignment,
                .live_from = from,
                .live_through = through,
            },
        });
    }

    fn build(self: *Builder, input: Input) !void {
        const trees = input.commitments;
        if (input.value_count == 0 or input.twiddle_words == 0 or input.fri.layers.len == 0)
            return error.InvalidCircuitResidentGeometry;
        // Public output values alias the witness value table and are mixed
        // after the preprocessed root, in the trace-commit stage.
        try self.add(.values, 0, try mul(input.value_count, 4), 64, .ingress, .trace_commit);
        const source_kinds = [_]Kind{ .preprocessed_source, .base_source, .interaction_source };
        for (source_kinds, 0..) |kind, tree_index| {
            for (trees[tree_index].column_logs, 0..) |log, ordinal|
                try self.add(kind, ordinal, try pow2(log), 64, if (tree_index == 2) .trace_commit else .ingress, if (input.retain_static and tree_index == 0) .proof_assembly else .trace_commit);
        }
        for (trees, 0..) |tree, ordinal| {
            const r = tree.requirements;
            const start: Stage = if (ordinal == 3) .constraint_evaluation else .trace_commit;
            try self.add(.commit_coefficients, ordinal, r.coefficient_words, 64, start, .oods);
            try self.add(.commit_evaluations, ordinal, r.evaluation_words, 64, start, .decommit);
            try self.add(.commit_logs, ordinal, r.column_log_words, 1, .ingress, start);
            try self.add(.commit_hashes, ordinal, try mul(r.merkle_hashes, 8), 64, start, .decommit);
            try self.add(.commit_layers, ordinal, try mul(r.merkle_layers, @sizeOf(field.MerkleLayerDescriptor) / 4), 2, .ingress, .decommit);
        }
        try self.add(.twiddles_forward, 0, input.twiddle_words, 64, .ingress, if (input.retain_static) .proof_assembly else .quotient);
        try self.add(.twiddles_inverse, 0, input.twiddle_words, 64, .ingress, if (input.retain_static) .proof_assembly else .fri_commit);
        try self.add(.transcript_state, 0, 16, 4, .trace_commit, .decommit);
        try self.add(.transcript_boundary, 0, 16, 4, .trace_commit, .decommit);
        try self.add(.transcript_salt, 0, 4, 4, .ingress, .trace_commit);
        try self.add(.transcript_config, 0, 8, 4, .ingress, .trace_commit);
        try self.add(.transcript_lookup, 0, 8, 4, .trace_commit, .constraint_evaluation);
        try self.add(.pow_prefix, 0, 8, 8, .trace_commit, .pow);
        try self.add(.pow_best, 0, 2, 2, .trace_commit, .pow);
        try self.add(.pow_completed, 0, 1, 1, .trace_commit, .pow);
        try self.add(.pow_nonce, 0, 2, 2, .trace_commit, .pow);
        try self.add(.circuit_hash, 0, 8, 8, .ingress, .trace_commit);
        try self.add(.error_flag, 0, 1, 1, .trace_generation, .fri_commit);
        try self.addInteraction(input.interaction);
        try self.addComposition(input.composition);
        try self.addOods(input.oods);
        try self.addQuotient(input.quotient, input.fri.layers[0].evaluation_log);
        try self.addFri(input.fri);
        try self.addDecommit(input.decommit);
        try self.add(.terminal_bundle, 0, input.terminal.total_words, 64, .ingress, .proof_assembly);
    }

    fn addInteraction(self: *Builder, plan: *const interaction.Plan) !void {
        const count = plan.row_counts.len;
        const pointer_words = @sizeOf(usize) / 4;
        const scratch = try plan.scratchWords();
        try self.add(.interaction_drawn, 0, 8, 4, .trace_commit, .trace_commit);
        try self.add(.interaction_powers, 0, 24, 4, .trace_commit, .constraint_evaluation);
        try self.add(.interaction_z, 0, 4, 4, .trace_commit, .constraint_evaluation);
        for (plan.row_counts, cuda.runtime.stages.circuit_interaction.secure_widths, 0..) |rows, width, index|
            try self.add(.interaction_denominator, index, try mul(try mul(rows, width), 4), 64, .trace_commit, .trace_commit);
        try self.add(.interaction_claims, 0, try mul(count, 4), 4, .trace_commit, .constraint_evaluation);
        try self.add(.interaction_pointer_table, 0, try mul(interaction.interaction_column_count, pointer_words), 2, .ingress, .trace_commit);
        inline for (.{ Kind.interaction_output_tables, Kind.interaction_denominator_tables, Kind.interaction_claim_tables }) |kind|
            try self.add(kind, 0, try mul(count, pointer_words), 2, .ingress, .trace_commit);
        try self.add(.interaction_geometry, 0, try mul(count, @sizeOf(cuda.abi.stages.relation.Geometry) / 4), 4, .ingress, .trace_commit);
        try self.add(.interaction_reduce, 0, scratch, 64, .trace_commit, .trace_commit);
        try self.add(.interaction_scan, 0, scratch, 64, .trace_commit, .trace_commit);
    }

    fn addComposition(self: *Builder, plan: *const composition.Plan) !void {
        const summary = plan.topology.summary;
        try self.add(.composition_constants, 0, plan.constants.len, 4, .ingress, .constraint_evaluation);
        try self.add(.composition_arguments, 0, try mul(plan.placements.len, @sizeOf(cuda.abi.stages.cairo_eval.Args) / 4), 2, .ingress, .constraint_evaluation);
        try self.add(.composition_trace_offsets, 0, @intCast(summary.trace_offset_words), 2, .ingress, .constraint_evaluation);
        try self.add(.composition_interaction_offsets, 0, @intCast(summary.interaction_offset_words), 2, .ingress, .constraint_evaluation);
        try self.add(.composition_lde_descriptors, 0, try mul(plan.topology.sources.len, @sizeOf(cuda.runtime.stages.transform.AddressedLdeDescriptor) / 4), 2, .ingress, .constraint_evaluation);
        try self.add(.composition_ext_descriptors, 0, try mul(plan.topology.extended_parameter_descriptors.len, @sizeOf(cuda.runtime.stages.cairo_eval.ExtSourceDescriptor) / 4), 4, .ingress, .constraint_evaluation);
        try self.add(.composition_ext_values, 0, @intCast(summary.extended_parameter_words), 4, .trace_commit, .constraint_evaluation);
        try self.add(.composition_denominators, 0, plan.denominator_inverses.len, 4, .ingress, .constraint_evaluation);
        try self.add(.composition_lde_tile, 0, @intCast(summary.lde_tile_words), 64, .constraint_evaluation, .constraint_evaluation);
        try self.add(.composition_accumulators, 0, @intCast(summary.accumulator_words), 64, .constraint_evaluation, .constraint_evaluation);
        try self.add(.composition_powers, 0, try mul(summary.constraint_count, 4), 4, .constraint_evaluation, .constraint_evaluation);
        try self.add(.composition_alpha, 0, 4, 4, .constraint_evaluation, .constraint_evaluation);
    }

    fn addOods(self: *Builder, plan: *const oods.Plan) !void {
        const samples = plan.offsets.len;
        try self.add(.oods_parameter, 0, 4, 4, .oods, .quotient);
        try self.add(.oods_offsets, 0, try mul(samples, @sizeOf(field.CirclePointBaseField) / 4), 2, .ingress, .oods);
        try self.add(.oods_folds, 0, samples, 1, .ingress, .oods);
        try self.add(.oods_indices, 0, samples, 1, .ingress, .oods);
        inline for (.{ Kind.oods_sample_points, Kind.oods_evaluation_points }) |kind|
            try self.add(kind, 0, try mul(samples, @sizeOf(field.SecureCirclePoint) / 4), 4, .oods, .quotient);
        try self.add(.oods_factors, 0, try mul(plan.factor_count, 4), 4, .oods, .oods);
        inline for (.{ Kind.oods_reduce_a, Kind.oods_reduce_b }) |kind|
            try self.add(kind, 0, try mul(plan.scratch_count, 4), 4, .oods, .oods);
        try self.add(.oods_values, 0, try mul(samples, 4), 4, .oods, .quotient);
    }

    fn addQuotient(self: *Builder, plan: *const quotient.Topology, fri_log: u32) !void {
        const terms = plan.prepared_terms.len;
        const groups = plan.group_log_sizes.len;
        try self.add(.quotient_challenge, 0, 4, 4, .oods, .quotient);
        try self.add(.quotient_terms, 0, try mul(terms, 5), 4, .ingress, .quotient);
        try self.add(.quotient_group_offsets, 0, groups + 1, 1, .ingress, .quotient);
        try self.add(.quotient_group_term_indices, 0, terms, 1, .ingress, .quotient);
        try self.add(.quotient_batch_terms, 0, try mul(terms, 3), 1, .ingress, .quotient);
        try self.add(.quotient_sources, 0, try mul(plan.sources.len, 4), 2, .ingress, .quotient);
        try self.add(.quotient_group_logs, 0, groups, 1, .ingress, .quotient);
        try self.add(.quotient_partial_logs, 0, groups, 1, .ingress, .quotient);
        try self.add(.quotient_partial_offsets, 0, try mul(groups + 1, 2), 2, .ingress, .quotient);
        try self.add(.quotient_term_points, 0, try mul(terms, 8), 8, .quotient, .quotient);
        try self.add(.quotient_lines, 0, try mul(terms, 12), 4, .quotient, .quotient);
        try self.add(.quotient_group_points, 0, try mul(groups, 8), 8, .quotient, .quotient);
        try self.add(.quotient_first_terms, 0, try mul(groups, 4), 4, .quotient, .quotient);
        try self.add(.quotient_partial_coordinates, 0, try mul(try mul(@as(usize, @intCast(plan.partial_offsets[groups])), 4), 1), 64, .quotient, .quotient);
        const rows = try pow2(fri_log);
        try self.add(.quotient_result, 0, try mul(rows, 4), 64, .quotient, .decommit);
        try self.add(.quotient_subdomain, 0, try mul(rows / 2, 4), 64, .quotient, .quotient);
        try self.add(.quotient_inverse_twiddles, 0, rows / 4, 64, .ingress, .quotient);
        try self.add(.quotient_coefficient_logs, 0, 4, 1, .ingress, .quotient);
    }

    fn addFri(self: *Builder, plan: *const fri.Plan) !void {
        try self.add(.fri_alpha, 0, 4, 4, .fri_commit, .fri_commit);
        for (plan.layers, 0..) |layer, ordinal| {
            if (ordinal != 0) try self.add(.fri_coordinates, ordinal, try mul(layer.evaluation_size, 4), 64, .fri_commit, .decommit);
            try self.add(.fri_hashes, ordinal, try mul(try addSize(try mul(layer.evaluation_size >> 2, 2), 0) - 1, 8), 64, .fri_commit, .decommit);
            try self.add(.fri_layers, ordinal, try mul(layer.merkle_count, @sizeOf(field.MerkleLayerDescriptor) / 4), 2, .ingress, .decommit);
        }
        const rows = try pow2(plan.final_log);
        try self.add(.fri_last_evaluation, 0, try mul(rows, 4), 4, .fri_commit, .fri_commit);
        try self.add(.fri_last_coefficients, 0, try mul(rows, 4), 4, .fri_commit, .fri_commit);
        try self.add(.fri_degree_error, 0, 1, 1, .fri_commit, .fri_commit);
        try self.add(.fri_last_transcript, 0, try mul(try pow2(plan.final_degree_log), 4), 4, .fri_commit, .fri_commit);
    }

    fn addDecommit(self: *Builder, plan: *const decommit.Plan) !void {
        const topo = &plan.topology;
        const queries = topo.query_count;
        var max_expanded = queries;
        var max_log: usize = 0;
        for (topo.trace_openings) |opening| max_log = @max(max_log, opening.tree_log_size);
        for (topo.fri_openings) |opening| {
            max_expanded = @max(max_expanded, try mul(queries, try pow2(opening.fold_step)));
            max_log = @max(max_log, opening.evaluation_log_size);
        }
        inline for (.{ Kind.decommit_raw, Kind.decommit_unique, Kind.decommit_mapped }) |kind|
            try self.add(kind, 0, queries, 1, .decommit, .decommit);
        inline for (.{ Kind.decommit_walk, Kind.decommit_walk_scratch, Kind.decommit_expanded }) |kind|
            try self.add(kind, 0, max_expanded, 1, .decommit, .decommit);
        try self.add(.decommit_leaf_indices, 0, 1, 1, .decommit, .decommit);
        try self.add(.decommit_sparse_indices, 0, 1, 1, .decommit, .decommit);
        try self.add(.decommit_sparse_hashes, 0, 8, 8, .decommit, .decommit);
        try self.add(.decommit_counts, 0, 5, 1, .decommit, .decommit);
        try self.add(.decommit_level_offsets, 0, max_log + 1, 1, .decommit, .decommit);
        try self.add(.decommit_level_counts, 0, max_log + 1, 1, .decommit, .decommit);
        var column_cursor: usize = 0;
        for (topo.trace_openings, 0..) |opening, ordinal| {
            try self.add(.decommit_column_logs, ordinal, opening.column_count, 1, .ingress, .decommit);
            column_cursor += opening.column_count;
        }
        if (column_cursor != topo.column_log_sizes.len) return error.InvalidCircuitResidentGeometry;
    }
};

fn pow2(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.CircuitResidentSizeOverflow;
    return @as(usize, 1) << @intCast(log);
}
fn addSize(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.CircuitResidentSizeOverflow;
}
fn mul(a: anytype, b: anytype) !usize {
    return std.math.mul(usize, @intCast(a), @intCast(b)) catch error.CircuitResidentSizeOverflow;
}

test "recorded circuit recursion has one lifetime-checked CUDA arena" {
    const allocator = std.testing.allocator;
    const core = @import("stwo_core");
    const circuit = @import("stwo_circuit_frontend");
    const cpu = @import("stwo_circuit_cpu_integration");
    const air_aot = @import("air_aot.zig");
    const geometry_module = @import("geometry.zig");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air_aot.build(allocator, encoded);
    defer catalog.deinit();
    const layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(cpu.air.recorded_sizes);
    var bound = try cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&layout), &layout);
    defer bound.deinit();
    const fri_config = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri_config, layout.traceLogSize());
    var geometry = try geometry_module.Geometry.init(allocator, &layout, &bound, &catalog, config);
    defer geometry.deinit();
    var commits: [4]commit.Plan = undefined;
    var initialized: usize = 0;
    defer for (commits[0..initialized]) |*item| item.deinit();
    for (geometry.trees, &commits) |tree, *item| {
        item.* = try commit.Plan.init(allocator, tree, fri_config.log_blowup_factor);
        initialized += 1;
    }
    var relation = try interaction.Plan.init(&layout);
    var evaluator = try composition.Plan.init(allocator, &layout, &bound, &catalog);
    defer evaluator.deinit();
    var sampler = try oods.Plan.init(allocator, &bound, &geometry, fri_config.log_blowup_factor);
    defer sampler.deinit();
    var quotient_topology = try quotient.derive(allocator, &bound, &geometry, &sampler, fri_config.log_blowup_factor);
    defer quotient_topology.deinit();
    const twiddle_words = try pow2(geometry.fri_input_log - 1);
    var fri_plan = try fri.Plan.init(allocator, &geometry, config, twiddle_words);
    defer fri_plan.deinit();
    var openings = try decommit.Plan.init(allocator, &geometry, config);
    defer openings.deinit();
    var proof = try terminal.init(allocator, &geometry, &sampler, &openings, config);
    defer proof.deinit(allocator);
    var plan = try Plan.init(allocator, .{
        .value_count = 4,
        .twiddle_words = twiddle_words,
        .commitments = &commits,
        .interaction = &relation,
        .composition = &evaluator,
        .oods = &sampler,
        .quotient = &quotient_topology,
        .fri = &fri_plan,
        .decommit = &openings,
        .terminal = &proof,
    });
    defer plan.deinit();
    try std.testing.expect((try plan.bytes()) > proof.total_words * 4);
    try std.testing.expectEqual(proof.total_words, (try plan.slot(.terminal_bundle, 0)).requirement.words);
    try std.testing.expectEqual(try mul(fri_plan.layers[0].evaluation_size, 4), (try plan.slot(.quotient_result, 0)).requirement.words);
    try std.testing.expectError(error.MissingCircuitResidentSlot, plan.slot(.fri_coordinates, 0));
    std.debug.print("circuit_cuda_recorded_arena_bytes={d}\n", .{try plan.bytes()});
}
