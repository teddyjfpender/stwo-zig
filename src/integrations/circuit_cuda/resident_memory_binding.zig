//! Typed views of the circuit recursion transaction's one GPU arena.
//! Every extent comes from `resident_memory_plan`; proof stages cannot
//! allocate side buffers or rebuild pointers after ingress.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const field = cuda.abi.field;
const shared = @import("stwo_native_cuda_integration").common;
const memory = @import("resident_memory_plan.zig");
const commit = @import("resident_commit.zig");
const interaction = @import("resident_interaction.zig");
const composition = @import("resident_composition_controller.zig");
const oods = @import("resident_oods.zig");
const fri = @import("resident_fri.zig");
const transcript = @import("resident_transcript.zig");
const terminal = @import("resident_terminal_bundle.zig");
const cairo = @import("stwo_cairo_cuda_integration");
const Quotient = cairo.executor.quotient.controller.QuotientBindings;

pub const Input = struct {
    plans: *const memory.Plan,
    commitments: *const [4]commit.Plan,
    interaction: *const interaction.Plan,
    fri: *const fri.Plan,
    terminal: *const terminal.Bundle,
    output_count: usize,
};

pub const Views = struct {
    allocator: std.mem.Allocator,
    values: common.Words,
    output_values: common.SecureFields,
    preprocessed: []common.Words,
    base: []common.Words,
    interaction_columns: []common.Words,
    coefficient_columns: [3][]common.Words,
    evaluation_columns: [3][]common.Words,
    commits: [4]commit.Buffers,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    transcript: transcript.Bindings,
    interaction: interaction.Buffers,
    composition: composition.Buffers,
    oods: shared.resident_views.Oods,
    quotient: Quotient,
    fri: shared.resident_views.Fri,
    decommit: shared.resident_views.Decommit,
    proof: shared.resident_views.Proof,
    circuit_hash: common.Words,
    error_flag: common.Words,

    pub fn deinit(self: *Views) void {
        self.allocator.free(self.preprocessed);
        self.allocator.free(self.base);
        self.allocator.free(self.interaction_columns);
        for (self.coefficient_columns) |columns| self.allocator.free(columns);
        for (self.evaluation_columns) |columns| self.allocator.free(columns);
        self.allocator.free(self.interaction.denominators);
        self.* = undefined;
    }
};

pub fn bind(
    allocator: std.mem.Allocator,
    transaction: *cuda.runtime.proof_transaction.ResidentProofTransaction,
    input: Input,
) !Views {
    return bindWith(allocator, transaction, input);
}

pub fn bindWith(allocator: std.mem.Allocator, transaction: anytype, input: Input) !Views {
    const binder = Binder(@TypeOf(transaction)){ .tx = transaction, .plan = input.plans };
    const arena_words = try transaction.residentArenaWords();
    const values = try binder.words(.values, 0);
    const output_first = @import("stwo_circuit_frontend").witness.trace.U_VAR_IDX + 1;
    if (input.output_count == 0 or output_first + input.output_count > values.len / 4)
        return error.InvalidCircuitResidentOutput;
    const output_values = try (try values.sub(output_first * 4, input.output_count * 4)).cast(field.SecureField);
    const twiddles_forward = try binder.words(.twiddles_forward, 0);
    const twiddles_inverse = try binder.words(.twiddles_inverse, 0);
    const error_flag = try binder.words(.error_flag, 0);

    var sources: [3][]common.Words = undefined;
    var source_count: usize = 0;
    errdefer for (sources[0..source_count]) |slice| allocator.free(slice);
    const source_kinds = [_]memory.Kind{ .preprocessed_source, .base_source, .interaction_source };
    for (source_kinds, 0..) |kind, tree| {
        const columns = try allocator.alloc(common.Words, input.commitments[tree].column_logs.len);
        sources[tree] = columns;
        source_count += 1;
        for (columns, 0..) |*out, index| out.* = try binder.words(kind, index);
    }
    var coefficient_columns: [3][]common.Words = undefined;
    var evaluation_columns: [3][]common.Words = undefined;
    var column_count: usize = 0;
    errdefer {
        for (coefficient_columns[0..column_count]) |slice| allocator.free(slice);
        for (evaluation_columns[0..column_count]) |slice| allocator.free(slice);
    }
    var commits: [4]commit.Buffers = undefined;
    for (input.commitments, &commits, 0..) |plan, *out, tree| {
        out.* = .{
            .coefficients = try binder.words(.commit_coefficients, tree),
            .evaluations = try binder.words(.commit_evaluations, tree),
            .column_logs = try binder.words(.commit_logs, tree),
            .merkle_hashes = try binder.as(field.Blake2sHash, .commit_hashes, tree),
            .merkle_layers = try binder.as(field.MerkleLayerDescriptor, .commit_layers, tree),
            .forward_twiddles = twiddles_forward,
            .inverse_twiddles = twiddles_inverse,
        };
        try out.validate(&plan);
        if (tree < 3) {
            const coeff = try allocator.alloc(common.Words, plan.column_logs.len);
            errdefer allocator.free(coeff);
            const eval = try allocator.alloc(common.Words, plan.column_logs.len);
            coefficient_columns[tree] = coeff;
            evaluation_columns[tree] = eval;
            column_count += 1;
            for (plan.cohorts) |cohort| {
                const coeff_rows = try pow2(cohort.trace_log);
                const eval_rows = try pow2(cohort.evaluation_log);
                for (0..cohort.count) |local| {
                    const index = cohort.first_column + local;
                    coeff[index] = try out.coefficients.sub(cohort.coefficient_offset + local * coeff_rows, coeff_rows);
                    eval[index] = try out.evaluations.sub(cohort.evaluation_offset + local * eval_rows, eval_rows);
                }
            }
        }
    }

    const transcript_view = transcript.Bindings{
        .state = try binder.words(.transcript_state, 0),
        .boundary_snapshot = try binder.words(.transcript_boundary, 0),
        .salt = try binder.words(.transcript_salt, 0),
        .fri_config = try binder.words(.transcript_config, 0),
        .lookup = try binder.as(field.SecureField, .transcript_lookup, 0),
        .pow_prefix = try binder.words(.pow_prefix, 0),
        .pow_best_nonce = try binder.as(u64, .pow_best, 0),
        .pow_completed_blocks = try binder.words(.pow_completed, 0),
        .pow_nonce_words = try binder.words(.pow_nonce, 0),
    };
    try transcript_view.validate();
    const relation_view = try bindInteraction(allocator, &binder, input.interaction, sources, output_values, transcript_view.lookup, error_flag);
    errdefer allocator.free(relation_view.denominators);
    const composition_view = composition.Buffers{
        .arena = arena_words,
        .sources = .{ .coefficients = coefficient_columns, .evaluations = evaluation_columns },
        .base_parameters = try binder.words(.composition_constants, 0),
        .arguments = try binder.as(cuda.runtime.stages.cairo_eval.Args, .composition_arguments, 0),
        .trace_offsets = try binder.words(.composition_trace_offsets, 0),
        .interaction_offsets = try binder.words(.composition_interaction_offsets, 0),
        .lde_descriptors = try binder.as(cuda.runtime.stages.transform.AddressedLdeDescriptor, .composition_lde_descriptors, 0),
        .extended_descriptors = try binder.as(cuda.runtime.stages.cairo_eval.ExtSourceDescriptor, .composition_ext_descriptors, 0),
        .extended_parameters = try binder.words(.composition_ext_values, 0),
        .denominator_inverses = try binder.words(.composition_denominators, 0),
        .lde_tile = try binder.words(.composition_lde_tile, 0),
        .accumulators = try binder.words(.composition_accumulators, 0),
        .random_powers = try binder.as(field.SecureField, .composition_powers, 0),
        .alpha = try binder.as(field.SecureField, .composition_alpha, 0),
        .relation_z = relation_view.z,
        .relation_alpha_powers = relation_view.alpha_powers,
        .claimed_sums = relation_view.claimed_sums,
        .composition_coefficients = commits[3].coefficients,
        .forward_twiddles = twiddles_forward,
        .inverse_twiddles = twiddles_inverse,
    };
    const oods_view = shared.resident_views.Oods{
        .parameter = try binder.as(field.SecureField, .oods_parameter, 0),
        .offset_points = try binder.as(field.CirclePointBaseField, .oods_offsets, 0),
        .fold_counts = try binder.words(.oods_folds, 0),
        .output_indices = try binder.words(.oods_indices, 0),
        .sample_points = try binder.as(field.SecureCirclePoint, .oods_sample_points, 0),
        .evaluation_points = try binder.as(field.SecureCirclePoint, .oods_evaluation_points, 0),
        .folding_factors = try binder.as(field.SecureField, .oods_factors, 0),
        .reduce_a = try binder.as(field.SecureField, .oods_reduce_a, 0),
        .reduce_b = try binder.as(field.SecureField, .oods_reduce_b, 0),
        .sampled_values = try binder.as(field.SecureField, .oods_values, 0),
    };
    const quotient_view = try bindQuotient(&binder, input.fri.layers[0].evaluation_log);
    const fri_view = try bindFri(&binder, input.fri);
    const decommit_view = try bindDecommit(&binder);
    const proof_view = try shared.resident_proof_binding.bindAt(shared.proof_bundle, transaction, (try input.plans.slot(.terminal_bundle, 0)).requirement.id, 0, .{ .proof = input.terminal.* });
    const output = Views{
        .allocator = allocator,
        .values = values,
        .output_values = output_values,
        .preprocessed = sources[0],
        .base = sources[1],
        .interaction_columns = sources[2],
        .coefficient_columns = coefficient_columns,
        .evaluation_columns = evaluation_columns,
        .commits = commits,
        .twiddles_forward = twiddles_forward,
        .twiddles_inverse = twiddles_inverse,
        .transcript = transcript_view,
        .interaction = relation_view,
        .composition = composition_view,
        .oods = oods_view,
        .quotient = quotient_view,
        .fri = fri_view,
        .decommit = decommit_view,
        .proof = proof_view,
        .circuit_hash = try binder.words(.circuit_hash, 0),
        .error_flag = error_flag,
    };
    return output;
}

fn Binder(comptime Provider: type) type {
    return struct {
        tx: Provider,
        plan: *const memory.Plan,

        fn words(self: *const @This(), kind: memory.Kind, index: usize) !common.Words {
            const descriptor = try self.plan.slot(kind, @intCast(index));
            const value = try self.tx.slot(descriptor.requirement.id);
            if (value.len != descriptor.requirement.words) return error.InvalidCircuitResidentSlot;
            return value;
        }
        fn as(self: *const @This(), comptime F: type, kind: memory.Kind, index: usize) !cuda.runtime.column.DeviceSlice(F) {
            return (try self.words(kind, index)).cast(F);
        }
    };
}

fn bindInteraction(
    allocator: std.mem.Allocator,
    binder: anytype,
    plan: *const interaction.Plan,
    sources: [3][]common.Words,
    outputs: common.SecureFields,
    lookup: common.SecureFields,
    error_flag: common.Words,
) !interaction.Buffers {
    const denominators = try allocator.alloc(common.SecureFields, plan.row_counts.len);
    errdefer allocator.free(denominators);
    for (denominators, 0..) |*view, index| view.* = try binder.as(field.SecureField, .interaction_denominator, index);
    return .{
        .preprocessed_columns = sources[0],
        .base_columns = sources[1],
        .interaction_columns = sources[2],
        .drawn_z_alpha = lookup,
        .alpha_powers = try binder.as(field.SecureField, .interaction_powers, 0),
        .z = try binder.as(field.SecureField, .interaction_z, 0),
        .denominators = denominators,
        .claimed_sums = try binder.as(field.SecureField, .interaction_claims, 0),
        .output_values = outputs,
        .error_flag = error_flag,
        .output_pointer_table = try binder.words(.interaction_pointer_table, 0),
        .output_tables = try binder.words(.interaction_output_tables, 0),
        .denominator_tables = try binder.words(.interaction_denominator_tables, 0),
        .claimed_sum_tables = try binder.words(.interaction_claim_tables, 0),
        .geometry = try binder.as(cuda.abi.stages.relation.Geometry, .interaction_geometry, 0),
        .reduction_partials = try binder.words(.interaction_reduce, 0),
        .scan_block_sums = try binder.words(.interaction_scan, 0),
    };
}

fn bindQuotient(binder: anytype, fri_log: u32) !Quotient {
    const partial = try binder.words(.quotient_partial_coordinates, 0);
    if (partial.len % 4 != 0) return error.InvalidCircuitResidentQuotient;
    const partial_rows = partial.len / 4;
    var partial_coordinates: [4]common.Words = undefined;
    for (&partial_coordinates, 0..) |*out, index| out.* = try partial.sub(index * partial_rows, partial_rows);
    const result = try binder.words(.quotient_result, 0);
    const rows = try pow2(fri_log);
    if (result.len != rows * 4) return error.InvalidCircuitResidentQuotient;
    return .{
        .subdomain_coordinates = try binder.words(.quotient_subdomain, 0),
        .subdomain_inverse_twiddles = try binder.words(.quotient_inverse_twiddles, 0),
        .coefficient_logs = try binder.words(.quotient_coefficient_logs, 0),
        .challenge = try binder.as(field.SecureField, .quotient_challenge, 0),
        .prepared_terms = try binder.as(cuda.abi.stages.quotient.PreparedTermDescriptor, .quotient_terms, 0),
        .group_offsets = try binder.words(.quotient_group_offsets, 0),
        .group_term_indices = try binder.words(.quotient_group_term_indices, 0),
        .batch_terms = try binder.as(cuda.abi.stages.quotient.BatchTermDescriptor, .quotient_batch_terms, 0),
        .source_descriptors = try binder.as(cuda.abi.stages.quotient.AddressedSourceDescriptor, .quotient_sources, 0),
        .group_log_sizes = try binder.words(.quotient_group_logs, 0),
        .partial_log_sizes = try binder.words(.quotient_partial_logs, 0),
        .partial_offsets = try binder.as(u64, .quotient_partial_offsets, 0),
        .term_points = try binder.as(field.SecureCirclePoint, .quotient_term_points, 0),
        .line_coefficients = try binder.as(field.SecureField, .quotient_lines, 0),
        .group_points = try binder.as(field.SecureCirclePoint, .quotient_group_points, 0),
        .first_linear_terms = try binder.as(field.SecureField, .quotient_first_terms, 0),
        .partial_coordinates = partial_coordinates,
        .result_coordinates = .{
            .c0 = try result.sub(0, rows),
            .c1 = try result.sub(rows, rows),
            .c2 = try result.sub(2 * rows, rows),
            .c3 = try result.sub(3 * rows, rows),
        },
    };
}

fn bindFri(binder: anytype, plan: *const fri.Plan) !shared.resident_views.Fri {
    var layers: [shared.resident_views.max_fri_layers]shared.resident_views.FriLayer = undefined;
    for (plan.layers, 0..) |layer, index| {
        const coordinates = if (index == 0) try binder.words(.quotient_result, 0) else try binder.words(.fri_coordinates, index);
        layers[index] = .{
            .coordinates = .{ .storage = coordinates, .column_stride_words = layer.evaluation_size },
            .merkle_hashes = try binder.as(field.Blake2sHash, .fri_hashes, index),
            .merkle_layers = try binder.as(field.MerkleLayerDescriptor, .fri_layers, index),
        };
    }
    return .{
        .alpha = try binder.as(field.SecureField, .fri_alpha, 0),
        .layers = layers,
        .layer_count = plan.layers.len,
        .last_evaluation = try binder.as(field.SecureField, .fri_last_evaluation, 0),
        .last_coefficients = try binder.as(field.SecureField, .fri_last_coefficients, 0),
        .last_degree_error = try binder.words(.fri_degree_error, 0),
        .last_transcript = try binder.as(field.SecureField, .fri_last_transcript, 0),
    };
}

fn bindDecommit(binder: anytype) !shared.resident_views.Decommit {
    const counts = try binder.words(.decommit_counts, 0);
    return .{
        .raw_queries = try binder.words(.decommit_raw, 0),
        .unique_queries = try binder.words(.decommit_unique, 0),
        .mapped_queries = try binder.words(.decommit_mapped, 0),
        .walk_queries = try binder.words(.decommit_walk, 0),
        .walk_scratch = try binder.words(.decommit_walk_scratch, 0),
        .leaf_indices = try binder.words(.decommit_leaf_indices, 0),
        .expanded_positions = try binder.words(.decommit_expanded, 0),
        .sparse_indices = try binder.words(.decommit_sparse_indices, 0),
        .sparse_hashes = try binder.as(field.Blake2sHash, .decommit_sparse_hashes, 0),
        .counts = .{
            .unique = try counts.sub(0, 1),
            .mapped_or_tree = try counts.sub(1, 1),
            .walk = try counts.sub(2, 1),
            .expanded = try counts.sub(3, 1),
            .leaf_or_sparse = try counts.sub(4, 1),
        },
        .sparse_level_offsets = try binder.words(.decommit_level_offsets, 0),
        .sparse_level_counts = try binder.words(.decommit_level_counts, 0),
        .preprocessed_column_log_sizes = try binder.words(.decommit_column_logs, 0),
        .main_column_log_sizes = try binder.words(.decommit_column_logs, 1),
        .interaction_column_log_sizes = try binder.words(.decommit_column_logs, 2),
        .composition_column_log_sizes = try binder.words(.decommit_column_logs, 3),
    };
}

fn pow2(log: u32) !usize {
    if (log >= @bitSizeOf(usize)) return error.InvalidCircuitResidentGeometry;
    return @as(usize, 1) << @intCast(log);
}

test "circuit resident binding typechecks all stage views" {
    const entry: *const fn (std.mem.Allocator, *cuda.runtime.proof_transaction.ResidentProofTransaction, Input) anyerror!Views = &bind;
    try std.testing.expect(@intFromPtr(entry) != 0);
}

test "recorded recursion layout binds every resident view without overlap" {
    const allocator = std.testing.allocator;
    const core = @import("stwo_core");
    const circuit = @import("stwo_circuit_frontend");
    const cpu = @import("stwo_circuit_cpu_integration");
    const air_aot = @import("air_aot.zig");
    const geometry_module = @import("geometry.zig");
    const composition_plan = @import("resident_composition.zig");
    const quotient_plan = @import("resident_quotient.zig");
    const decommit_plan = @import("resident_decommit.zig");
    const encoded = try std.fs.cwd().readFileAlloc(allocator, cpu.air.bundle_path, 16 << 20);
    defer allocator.free(encoded);
    var template = try cpu.air.parse(allocator, encoded);
    defer template.deinit();
    var catalog = try air_aot.build(allocator, encoded);
    defer catalog.deinit();
    const column_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(cpu.air.recorded_sizes);
    var air = try cpu.air.bind(allocator, &template, try circuit.common.component_list.circuitComponentLogSizes(&column_layout), &column_layout);
    defer air.deinit();
    const fri_config = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const config = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri_config, column_layout.traceLogSize());
    var geometry = try geometry_module.Geometry.init(allocator, &column_layout, &air, &catalog, config);
    defer geometry.deinit();
    var commits: [4]commit.Plan = undefined;
    var initialized: usize = 0;
    defer for (commits[0..initialized]) |*item| item.deinit();
    for (geometry.trees, &commits) |tree, *item| {
        item.* = try commit.Plan.init(allocator, tree, fri_config.log_blowup_factor);
        initialized += 1;
    }
    const relation = try interaction.Plan.init(&column_layout);
    var evaluator = try composition_plan.Plan.init(allocator, &column_layout, &air, &catalog);
    defer evaluator.deinit();
    var sampler = try oods.Plan.init(allocator, &air, &geometry, fri_config.log_blowup_factor);
    defer sampler.deinit();
    var quotient_topology = try quotient_plan.derive(allocator, &air, &geometry, &sampler, fri_config.log_blowup_factor);
    defer quotient_topology.deinit();
    const twiddle_words = try pow2(geometry.fri_input_log - 1);
    var fri_plan = try fri.Plan.init(allocator, &geometry, config, twiddle_words);
    defer fri_plan.deinit();
    var openings = try decommit_plan.Plan.init(allocator, &geometry, config);
    defer openings.deinit();
    var proof = try terminal.init(allocator, &geometry, &sampler, &openings, config);
    defer proof.deinit(allocator);
    var plan = try memory.Plan.init(allocator, .{
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
    const Fake = struct {
        placement: *const cuda.runtime.arena.Plan,
        const base: usize = 0x1000_0000_000;

        pub fn slot(self: *@This(), id: u32) !common.Words {
            const placed = try self.placement.placement(id);
            return .{
                .address = base + placed.offset_words * 4,
                .len = placed.requirement.words,
                .owner = 1,
                .generation = 1,
            };
        }
        pub fn residentArenaWords(self: *@This()) !common.Words {
            return .{ .address = base, .len = self.placement.total_words, .owner = 1, .generation = 1 };
        }
    };
    var fake = Fake{ .placement = &plan.placement };
    var views = try bindWith(allocator, &fake, .{
        .plans = &plan,
        .commitments = &commits,
        .interaction = &relation,
        .fri = &fri_plan,
        .terminal = &proof,
        .output_count = 1,
    });
    defer views.deinit();
    _ = try interaction.Bound.init(&relation, views.interaction);
    var composed = try composition.Bound.init(allocator, &evaluator, views.composition);
    defer composed.deinit();
    try fri_plan.validate(views.fri, views.twiddles_inverse);
    try std.testing.expectEqual(views.proof.decommitment.address, views.proof.bundle.address + proof.section(.decommitment).offset_words * 4);
}
