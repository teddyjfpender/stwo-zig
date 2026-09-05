//! Focused shard of binary_fri_outer_source_test.zig; import that suite facade.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const authority = @import("binary_pair_authority.zig");
pub const captured_fri = @import("captured_fri.zig");
pub const fixed_wire = @import("fixed_wire.zig");
pub const fixture_mod = @import("binary_pair_test_fixture.zig");
pub const protocol = @import("protocol.zig");
pub const sample_point_layout = @import("sample_point_layout.zig");
pub const source_mod = @import("binary_fri_outer_source.zig");
pub const bundle_mod = @import("binary_fri_outer_bundle.zig");
pub const transcript_program = @import("transcript_program.zig");
pub const air = @import("air/mod.zig");

pub const DIMENSIONS = fixture_mod.DIMENSIONS;
pub const Prepared = authority.Prepared(DIMENSIONS);
pub const Source = source_mod.Source(DIMENSIONS);
pub const Bundle = bundle_mod.Bundle(DIMENSIONS);
pub const Wire = fixture_mod.Wire;
pub const TRACE_COLUMN_COUNTS = [4]usize{ 1, 1, 8, 1 };
pub const POSEIDON2_SAMPLE_LAYOUT_START: u32 = 2;

pub const FullComposition = struct {
    profile: source_mod.TrustedCompositionProfileV1,
    graph: air.composition_circuit.CircuitGraph,
    evaluation: air.verifier_arithmetic_lowering.Evaluation,
    poseidon2_partials: [source_mod.POSEIDON2_PARTIAL_COUNT]QM31,
    poseidon2_roster_total: QM31,
};

pub fn buildFullComposition(
    allocator: std.mem.Allocator,
    pair: *const fixture_mod.HonestFixture,
    prepared: *const Prepared,
    child: *const CaptureFixture,
    child_index: usize,
) !FullComposition {
    const poseidon2_partials = testPoseidonPartials(pair, child_index);
    const poseidon2_roster_total = testPoseidonTotal(pair, child_index);
    const input_profile = air.composition_circuit.InputProfile{
        .sampled_value_count = @intCast(child.capture.sampled_values.len),
        .claimed_sum_count = source_mod.COMPOSITION_CLAIMED_SUM_COUNT,
        .relation_challenge_count = @intCast(
            prepared.executions[child_index].relationChallengeCount(),
        ),
    };
    const input_count = try air.composition_circuit.recursionInputCount(
        input_profile,
    );
    const nodes = try allocator.alloc(
        air.composition_circuit.Node,
        input_count + 5,
    );
    const bindings = try allocator.alloc(
        air.composition_circuit.RecursionInputBinding,
        input_count,
    );
    const values = try allocator.alloc(QM31, nodes.len);
    for (nodes[0..input_count], bindings, values[0..input_count], 0..) |
        *node,
        *binding,
        *value,
        input_index,
    | {
        const input_source = air.composition_circuit.expectedRecursionSource(
            input_profile,
            input_index,
        ) orelse return error.InvalidFixture;
        node.* = .{ .op = .input };
        binding.* = .{ .node_id = @intCast(input_index), .source = input_source };
        value.* = QM31.fromM31Array(.{
            try fullCompositionInputValue(
                pair,
                prepared,
                child,
                child_index,
                poseidon2_partials,
                input_source,
            ),
            M31.zero(),
            M31.zero(),
            M31.zero(),
        });
    }

    const mul_index = input_count;
    const inverse_index = input_count + 1;
    const add_index = input_count + 2;
    const constant_index = input_count + 3;
    const output_index = input_count + 4;
    nodes[mul_index] = .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 0 } } };
    values[mul_index] = values[0].mul(values[0]);
    nodes[inverse_index] = .{ .op = .{ .inverse = 0 } };
    values[inverse_index] = try values[0].inv();
    nodes[add_index] = .{ .op = .{ .add = .{
        .lhs = @intCast(mul_index),
        .rhs = @intCast(inverse_index),
    } } };
    values[add_index] = values[mul_index].add(values[inverse_index]);
    nodes[constant_index] = .{ .op = .{ .constant = .{ 2, 0, 0, 0 } } };
    values[constant_index] = QM31.fromM31Array(.{
        M31.fromCanonical(2),
        M31.zero(),
        M31.zero(),
        M31.zero(),
    });
    nodes[output_index] = .{ .op = .{ .sub = .{
        .lhs = @intCast(add_index),
        .rhs = @intCast(constant_index),
    } } };
    values[output_index] = values[add_index].sub(values[constant_index]);
    const outputs = try allocator.alloc(u32, 1);
    outputs[0] = @intCast(output_index);
    const graph_digest = air.composition_circuit.computeGraphDigest(nodes, outputs);
    const graph = try air.composition_circuit.CircuitGraph.authenticate(
        nodes,
        outputs,
        graph_digest,
    );
    const profile = try source_mod.TrustedCompositionProfileV1.sealRecorded(
        pair.shape.air_program_id,
        @intCast(501 + child_index),
        graph_digest,
        graph_digest,
        .segment_leaf,
        input_profile,
        bindings,
        POSEIDON2_SAMPLE_LAYOUT_START,
    );
    return .{
        .profile = profile,
        .graph = graph,
        .evaluation = .{
            .circuit_identity = graph.identity_digest,
            .values = values,
        },
        .poseidon2_partials = poseidon2_partials,
        .poseidon2_roster_total = poseidon2_roster_total,
    };
}

pub fn fullCompositionInputValue(
    pair: *const fixture_mod.HonestFixture,
    prepared: *const Prepared,
    child: *const CaptureFixture,
    child_index: usize,
    poseidon2_partials: [source_mod.POSEIDON2_PARTIAL_COUNT]QM31,
    input_source: air.composition_circuit.RecursionSource,
) !M31 {
    return switch (input_source) {
        .parent_binary_selector => M31.one(),
        .child_kind_selector => |kind| M31.fromCanonical(
            @intFromBool(kind == .segment_leaf),
        ),
        .statement_word => |word| blk: {
            const words = if (child_index == 0)
                &prepared.left_words
            else
                &prepared.right_words;
            if (word >= words.len) return error.InvalidFixture;
            break :blk words[word];
        },
        .sampled_value => |coordinate| blk: {
            if (coordinate.item_index >= child.capture.sampled_values.len or
                coordinate.word_index >= 4)
            {
                return error.InvalidFixture;
            }
            break :blk child.capture.sampled_values[coordinate.item_index]
                .toM31Array()[coordinate.word_index];
        },
        .claimed_sum => |coordinate| blk: {
            const sums = pair.wires[child_index].claimed_sums;
            if (coordinate.word_index >= 4)
                return error.InvalidFixture;
            const item_index: usize = @intCast(coordinate.item_index);
            if (item_index < sums.len) break :blk M31.fromCanonical(
                sums[item_index][coordinate.word_index],
            );
            if (item_index >= source_mod.COMPOSITION_CLAIMED_SUM_COUNT)
                return error.InvalidFixture;
            break :blk poseidon2_partials[
                item_index - source_mod.POSEIDON2_PARTIAL_CLAIM_START
            ].toM31Array()[coordinate.word_index];
        },
        .relation_challenge => |coordinate| blk: {
            var challenge_at: usize = 0;
            for (prepared.executions[child_index].operations) |operation| switch (operation.step) {
                .draw_relation_challenge => {
                    if (challenge_at == coordinate.challenge) {
                        const draw = operation.draw orelse return error.InvalidFixture;
                        if (coordinate.word_index >= draw.len)
                            return error.InvalidFixture;
                        break :blk draw[coordinate.word_index];
                    }
                    challenge_at += 1;
                },
                else => {},
            };
            return error.InvalidFixture;
        },
        .composition_randomness => |word| blk: {
            if (word >= 4) return error.InvalidFixture;
            break :blk child.capture.composition_randomness.toM31Array()[word];
        },
        .oods_point => |word| blk: {
            if (word >= 4) return error.InvalidFixture;
            break :blk child.capture.oods_seed.toM31Array()[word];
        },
        .public_wire_boundary, .transcript_claimed_sum => error.InvalidFixture,
    };
}

pub fn testPoseidonTotal(
    pair: *const fixture_mod.HonestFixture,
    child_index: usize,
) QM31 {
    const words = pair.wires[child_index]
        .claimed_sums[source_mod.POSEIDON2_ROSTER_ROW];
    return QM31.fromM31Array(.{
        M31.fromCanonical(words[0]),
        M31.fromCanonical(words[1]),
        M31.fromCanonical(words[2]),
        M31.fromCanonical(words[3]),
    });
}

pub fn testPoseidonPartials(
    pair: *const fixture_mod.HonestFixture,
    child_index: usize,
) [source_mod.POSEIDON2_PARTIAL_COUNT]QM31 {
    const first = QM31.fromU32Unchecked(
        @intCast(17 + child_index),
        @intCast(19 + child_index),
        @intCast(23 + child_index),
        @intCast(29 + child_index),
    );
    return .{ first, testPoseidonTotal(pair, child_index).sub(first) };
}

pub const CaptureFixture = struct {
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    capture: captured_fri.Owned,

    pub fn init(
        backing: std.mem.Allocator,
        wire: *const Wire,
        execution: *const transcript_program.Execution,
    ) !CaptureFixture {
        const arena = try backing.create(std.heap.ArenaAllocator);
        errdefer backing.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        const raw_queries = try allocator.alloc(M31, DIMENSIONS.query_count);
        const fri_alphas = try allocator.alloc(QM31, DIMENSIONS.fri_layer_count);
        const randomness = try transcriptValues(execution, raw_queries, fri_alphas);

        const fold_widths = try allocator.alloc(u32, 1);
        fold_widths[0] = 16;
        const fri_profile = air.fri_verifier_circuit.Profile{
            .lifting_log_size = 5,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .fold_widths = fold_widths,
            .query_count = DIMENSIONS.query_count,
        };
        var fri_circuit = try air.fri_verifier_circuit.build(allocator, fri_profile);

        const deep_answers = try zeros(QM31, allocator, DIMENSIONS.query_count);
        const authenticated = try zeros(
            QM31,
            allocator,
            DIMENSIONS.query_count * DIMENSIONS.maximum_fold_width,
        );
        const authenticated_layers = try allocator.alloc([]const QM31, 1);
        authenticated_layers[0] = authenticated;
        const fri_positions = try allocator.alloc(M31, DIMENSIONS.query_count);
        const fri_offsets = try allocator.alloc(M31, DIMENSIONS.query_count);
        const last_positions = try allocator.alloc(M31, DIMENSIONS.query_count);
        for (raw_queries, fri_positions, fri_offsets, last_positions) |
            raw,
            *position,
            *offset,
            *terminal,
        | {
            position.* = raw;
            offset.* = M31.fromCanonical(raw.toU32() & 15);
            terminal.* = M31.fromCanonical(raw.toU32() >> 4);
        }
        const fri_position_layers = try allocator.alloc([]const M31, 1);
        fri_position_layers[0] = fri_positions;
        const fri_offset_layers = try allocator.alloc([]const M31, 1);
        fri_offset_layers[0] = fri_offsets;
        const last_coefficients = try zeros(
            QM31,
            allocator,
            DIMENSIONS.last_layer_coefficient_count,
        );
        const fri_evaluation = try fri_circuit.evaluate(allocator, .{
            .active = true,
            .deep_answers = deep_answers,
            .authenticated_values = authenticated_layers,
            .fri_alphas = fri_alphas,
            .raw_queries = raw_queries,
            .fri_positions = fri_position_layers,
            .fri_offsets = fri_offset_layers,
            .last_layer_positions = last_positions,
            .last_layer_coefficients = last_coefficients,
        });

        const tree_heights = try allocator.alloc(u32, 4);
        @memset(tree_heights, 5);
        const column_log_storage = try allocator.alloc(u32, 11);
        @memset(column_log_storage, 5);
        const column_logs = try allocator.alloc([]const u32, 4);
        var column_at: usize = 0;
        for (column_logs, TRACE_COLUMN_COUNTS) |*logs, count| {
            logs.* = column_log_storage[column_at..][0..count];
            column_at += count;
        }
        std.debug.assert(column_at == column_log_storage.len);
        const sample_layouts = try allocator.alloc(
            sample_point_layout.Layout,
            11,
        );
        sample_layouts[0] = .current_previous;
        sample_layouts[1] = .current;
        @memset(sample_layouts[2..10], .current_previous);
        sample_layouts[10] = .none;
        const pcs_trees = try allocator.alloc(air.pcs_deep_circuit.TreeProfile, 4);
        for (pcs_trees, column_logs) |*tree, logs|
            tree.* = .{ .column_log_sizes = logs };
        var pcs_circuit = try air.pcs_deep_circuit.build(allocator, .{
            .trees = pcs_trees,
            .sample_layouts = sample_layouts,
            .lifting_log_size = 5,
            .log_blowup_factor = 1,
            .query_count = DIMENSIONS.query_count,
        });
        const sampled_values = try zeros(
            QM31,
            allocator,
            DIMENSIONS.sampled_value_count,
        );
        const queried_values = try zeros(
            M31,
            allocator,
            DIMENSIONS.queried_value_count,
        );
        const pcs_evaluation = try pcs_circuit.evaluate(allocator, .{
            .active = true,
            .sampled_values = sampled_values,
            .queried_values = queried_values,
            .oods_seed = randomness.oods,
            .deep_randomness = randomness.deep,
            .raw_queries = raw_queries,
            .answers = deep_answers,
        });

        const trace_siblings = try allocator.alloc([]const protocol.Digest, 4);
        for (trace_siblings, 0..) |*siblings, tree| {
            const storage = try allocator.alloc(
                protocol.Digest,
                DIMENSIONS.query_count * 5,
            );
            for (0..DIMENSIONS.query_count) |query| {
                for (0..5) |depth| storage[query * 5 + depth] =
                    wire.trace_paths[tree * DIMENSIONS.query_count + query].siblings[depth];
            }
            siblings.* = storage;
        }
        const fri_roots = try allocator.alloc(protocol.Digest, 1);
        fri_roots[0] = wire.fri_layers[0].commitment;
        const fri_sibling_storage = try allocator.alloc(
            protocol.Digest,
            DIMENSIONS.query_count,
        );
        for (fri_sibling_storage, 0..) |*sibling, query|
            sibling.* = wire.fri_layers[0].queries[query].path.siblings[0];
        const fri_siblings = try allocator.alloc([]const protocol.Digest, 1);
        fri_siblings[0] = fri_sibling_storage;
        const fri_layer_profiles = try allocator.alloc(
            air.fri_merkle_leaf_witness.LayerProfile,
            1,
        );
        fri_layer_profiles[0] = .{ .width = 16, .tree_height = 3 };
        const opening_words = try zeros(
            M31,
            allocator,
            DIMENSIONS.query_count * DIMENSIONS.maximum_fold_width * 4,
        );
        const fri_layer_openings = try allocator.alloc(
            air.fri_merkle_leaf_witness.LayerOpening,
            1,
        );
        fri_layer_openings[0] = .{ .width = 16, .values = opening_words };
        const qm31_storage = try zeros(
            QM31,
            allocator,
            DIMENSIONS.sampled_value_count + DIMENSIONS.query_count +
                DIMENSIONS.query_count * DIMENSIONS.maximum_fold_width +
                DIMENSIONS.fri_layer_count +
                DIMENSIONS.last_layer_coefficient_count,
        );
        const m31_storage = try zeros(
            M31,
            allocator,
            DIMENSIONS.queried_value_count + 4 * DIMENSIONS.query_count,
        );

        return .{
            .backing = backing,
            .arena = arena,
            .capture = .{
                .allocator = allocator,
                .circuit = fri_circuit,
                .evaluation = fri_evaluation,
                .pcs_circuit = pcs_circuit,
                .pcs_evaluation = pcs_evaluation,
                .fold_widths = fold_widths,
                .trace_tree_heights = tree_heights,
                .column_log_sizes = column_logs,
                .column_log_storage = column_log_storage,
                .sample_layouts = sample_layouts,
                .trace_siblings = trace_siblings,
                .authenticated_values = authenticated_layers,
                .fri_positions = fri_position_layers,
                .fri_offsets = fri_offset_layers,
                .fri_layer_profiles = fri_layer_profiles,
                .fri_layer_openings = fri_layer_openings,
                .fri_siblings = fri_siblings,
                .qm31_storage = qm31_storage,
                .m31_storage = m31_storage,
                .fri_opening_words = opening_words,
                .digest_storage = &.{},
                .sampled_values = sampled_values,
                .queried_values = queried_values,
                .deep_answers = deep_answers,
                .fri_alphas = fri_alphas,
                .raw_queries = raw_queries,
                .last_layer_positions = last_positions,
                .last_layer_coefficients = last_coefficients,
                .sampled_value_count = DIMENSIONS.sampled_value_count,
                .queried_values_per_query = 11,
                .interaction_pow_bits = 0,
                .pcs_pow_bits = 0,
                .claimed_sum_count = DIMENSIONS.claimed_sum_count,
                .trace_roots = &wire.commitments,
                .fri_roots = fri_roots,
                .composition_randomness = randomness.composition,
                .oods_seed = randomness.oods,
                .deep_randomness = randomness.deep,
            },
        };
    }

    pub fn deinit(self: *CaptureFixture) void {
        self.capture.pcs_evaluation.deinit();
        self.capture.pcs_circuit.deinit();
        self.capture.evaluation.deinit();
        self.capture.circuit.deinit();
        self.arena.deinit();
        self.backing.destroy(self.arena);
        self.* = undefined;
    }
};

pub const TranscriptValues = struct {
    composition: QM31,
    oods: QM31,
    deep: QM31,
};

pub fn transcriptValues(
    execution: *const transcript_program.Execution,
    raw_queries: []M31,
    alphas: []QM31,
) !TranscriptValues {
    var result: TranscriptValues = undefined;
    var saw_composition = false;
    var saw_oods = false;
    var saw_deep = false;
    var alpha_at: usize = 0;
    var query_at: usize = 0;
    for (execution.operations) |operation| switch (operation.step) {
        .draw_composition_randomness => {
            result.composition = secureDraw(operation);
            saw_composition = true;
        },
        .draw_oods_point => {
            result.oods = secureDraw(operation);
            saw_oods = true;
        },
        .draw_deep_randomness => {
            result.deep = secureDraw(operation);
            saw_deep = true;
        },
        .draw_fri_alpha => {
            alphas[alpha_at] = secureDraw(operation);
            alpha_at += 1;
        },
        .draw_query_block => |step| {
            const draw = operation.draw.?;
            const count: usize = @intCast(step.query_count);
            for (draw[0..count]) |word| {
                raw_queries[query_at] = M31.fromCanonical(word.toU32() & 31);
                query_at += 1;
            }
        },
        else => {},
    };
    if (!saw_composition or !saw_oods or !saw_deep or
        alpha_at != alphas.len or query_at != raw_queries.len)
    {
        return error.InvalidFixture;
    }
    return result;
}

pub fn secureDraw(operation: transcript_program.Operation) QM31 {
    return QM31.fromM31Array(operation.draw.?[0..4].*);
}

pub fn zeros(comptime T: type, allocator: std.mem.Allocator, count: usize) ![]T {
    const result = try allocator.alloc(T, count);
    @memset(result, switch (T) {
        M31 => M31.zero(),
        QM31 => QM31.zero(),
        else => @compileError("unsupported zero fixture type"),
    });
    return result;
}
