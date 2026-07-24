//! Geometry-checked XOR views over one prepared resident proof arena.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const constraint = @import("constraint.zig");
const geometry_mod = @import("geometry.zig");
const plan_mod = @import("plan.zig");
const slots = @import("slots.zig");
const views = @import("../common/resident_views.zig");

const Words = column.DeviceSlice(u32);

pub const Bound = struct {
    trees: views.TraceTrees,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    protocol_words: common.Words,
    statement_words: common.Words,
    transcript: Transcript,
    constraint_buffers: constraint.Buffers,
    proof: views.Proof,
};

pub const Transcript = struct {
    state: common.Words,
    input_snapshot: common.Words,
    output_snapshot: common.Words,
    boundary_snapshot: common.Words,
    protocol_words: common.Words,
    statement_words: common.Words,
};

pub fn bind(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !Bound {
    const geometry = prepared.logical.geometry;
    const rows = try geometry.traceRowCount();
    const committed_rows = geometry.commitment_rows;
    const hash_count = try sub(try mul(committed_rows, 2), 1);
    const layer_count = @as(usize, geometry.commitment_log_rows) + 1;
    const source_words = try exactWords(
        provider,
        slots.source_evaluations,
        try mul(geometry_mod.sampled_mask_points, committed_rows),
    );
    const preprocessed_evaluations = common.WordMatrix{
        .storage = try source_words.sub(
            0,
            try mul(geometry_mod.preprocessed_columns, committed_rows),
        ),
        .column_stride_words = committed_rows,
    };
    const main_offset = try mul(
        geometry_mod.preprocessed_columns,
        committed_rows,
    );
    const main_evaluations = common.WordMatrix{
        .storage = try source_words.sub(
            main_offset,
            try mul(geometry_mod.main_columns, committed_rows),
        ),
        .column_stride_words = committed_rows,
    };
    const composition_offset = try add(
        main_offset,
        try mul(geometry_mod.main_columns, committed_rows),
    );
    const composition_evaluations = common.WordMatrix{
        .storage = try source_words.sub(
            composition_offset,
            try mul(geometry_mod.composition_columns, committed_rows),
        ),
        .column_stride_words = committed_rows,
    };
    const preprocessed = try tree(
        provider,
        .preprocessed,
        slots.preprocessed_coefficients,
        preprocessed_evaluations,
        slots.preprocessed_log_sizes,
        slots.preprocessed_merkle_hashes,
        slots.preprocessed_merkle_layers,
        geometry_mod.preprocessed_columns,
        committed_rows,
        hash_count,
        layer_count,
    );
    const main = try tree(
        provider,
        .main,
        slots.main_coefficients,
        main_evaluations,
        slots.main_log_sizes,
        slots.main_merkle_hashes,
        slots.main_merkle_layers,
        geometry_mod.main_columns,
        committed_rows,
        hash_count,
        layer_count,
    );
    const composition = try tree(
        provider,
        .composition,
        slots.composition_coefficients,
        composition_evaluations,
        slots.composition_log_sizes,
        slots.composition_merkle_hashes,
        slots.composition_merkle_layers,
        geometry_mod.composition_columns,
        rows,
        hash_count,
        layer_count,
    );
    const statement_words = try exactWords(
        provider,
        slots.statement_words,
        4,
    );
    const challenge_words = try exactWords(
        provider,
        slots.composition_challenge,
        4,
    );
    const protocol_words = try exactWords(
        provider,
        slots.protocol_words,
        4,
    );
    const transcript = Transcript{
        .state = try exactWords(provider, slots.transcript_state, 16),
        .input_snapshot = try exactWords(
            provider,
            slots.transcript_input_snapshot,
            @max(try mul(geometry_mod.sampled_mask_points, 4), 16),
        ),
        .output_snapshot = try exactWords(
            provider,
            slots.transcript_output_snapshot,
            @max(geometry.protocol.fri_config.n_queries, 8),
        ),
        .boundary_snapshot = try exactWords(
            provider,
            slots.transcript_boundary_snapshot,
            16,
        ),
        .protocol_words = protocol_words,
        .statement_words = statement_words,
    };
    return .{
        .trees = try views.TraceTrees.init(&.{
            preprocessed,
            main,
            composition,
        }),
        .twiddles_forward = try exactWords(
            provider,
            slots.twiddles_forward,
            rows,
        ),
        .twiddles_inverse = try exactWords(
            provider,
            slots.twiddles_inverse,
            rows,
        ),
        .protocol_words = protocol_words,
        .statement_words = statement_words,
        .transcript = transcript,
        .constraint_buffers = .{
            .statement_parameters = statement_words,
            .challenge_parameters = challenge_words,
            .composition_coordinates = .{
                .storage = try exactWords(
                    provider,
                    slots.composition_coordinates,
                    try mul(4, committed_rows),
                ),
                .column_stride_words = committed_rows,
            },
        },
        .proof = try bindProof(provider, prepared),
    };
}

fn bindProof(
    provider: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !views.Proof {
    const bundle = try exactWords(
        provider,
        slots.proof_bundle,
        prepared.proof.total_words,
    );
    return .{
        .bundle = bundle,
        .degree_verdict = try bundle.sub(15, 1),
        .trace_commitments = try section(
            bundle,
            prepared,
            .trace_commitments,
        ),
        .sampled_values = try section(
            bundle,
            prepared,
            .sampled_values,
        ),
        .fri_commitments = try section(
            bundle,
            prepared,
            .fri_commitments,
        ),
        .fri_last_layer = try section(
            bundle,
            prepared,
            .fri_last_layer,
        ),
        .pow_nonce = try section(
            bundle,
            prepared,
            .proof_of_work,
        ),
        .decommitment = try section(
            bundle,
            prepared,
            .decommitment,
        ),
    };
}

fn section(
    bundle: Words,
    prepared: *const plan_mod.PreparedPlan,
    kind: @import("proof_bundle.zig").SectionKind,
) !Words {
    const descriptor = prepared.proof.section(kind);
    return bundle.sub(
        descriptor.offset_words,
        descriptor.words,
    );
}

fn tree(
    provider: anytype,
    role: @import("../common/uniform_layout.zig").TraceRole,
    coefficient_slot: slots.SlotId,
    evaluations: common.WordMatrix,
    log_slot: slots.SlotId,
    hash_slot: slots.SlotId,
    layer_slot: slots.SlotId,
    column_count: usize,
    coefficient_stride: usize,
    hash_count: usize,
    layer_count: usize,
) !views.TraceTree {
    return .{
        .role = role,
        .coefficients = .{
            .storage = try exactWords(
                provider,
                coefficient_slot,
                try mul(column_count, coefficient_stride),
            ),
            .column_stride_words = coefficient_stride,
        },
        .evaluations = evaluations,
        .column_log_sizes = try exactWords(
            provider,
            log_slot,
            column_count,
        ),
        .merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            hash_slot,
            hash_count,
        ),
        .merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            layer_slot,
            layer_count,
        ),
    };
}

fn exactWords(
    provider: anytype,
    id: slots.SlotId,
    expected: usize,
) !Words {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn exactAs(
    provider: anytype,
    comptime F: type,
    id: slots.SlotId,
    expected: usize,
) !column.DeviceSlice(F) {
    const words_per_element = @sizeOf(F) / @sizeOf(u32);
    const words = try exactWords(
        provider,
        id,
        try mul(expected, words_per_element),
    );
    const result = try words.cast(F);
    if (result.len != expected) return error.InvalidKernelDescriptor;
    return result;
}

fn sub(left: usize, right: usize) !usize {
    return std.math.sub(usize, left, right) catch error.SizeOverflow;
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

test "XOR binding exposes three independent role-indexed trees" {
    const pcs = @import("stwo_core").pcs;
    const geometry = try geometry_mod.admit(
        .{ .log_size = 8, .log_step = 3, .offset = 5 },
        pcs.PcsConfig.default(),
    );
    var prepared = try plan_mod.PreparedPlan.init(
        std.testing.allocator,
        geometry,
    );
    defer prepared.deinit(std.testing.allocator);
    const provider = TestProvider{ .prepared = &prepared };
    const bound = try bind(&provider, &prepared);
    try std.testing.expectEqual(@as(usize, 3), bound.trees.active().len);
    const preprocessed = try bound.trees.require(.preprocessed);
    const main = try bound.trees.require(.main);
    const composition = try bound.trees.require(.composition);
    try std.testing.expectEqual(@as(usize, 2), preprocessed.column_log_sizes.len);
    try std.testing.expectEqual(@as(usize, 1), main.column_log_sizes.len);
    try std.testing.expectEqual(@as(usize, 8), composition.column_log_sizes.len);
    try std.testing.expectEqual(geometry.commitment_rows, preprocessed.coefficients.column_stride_words);
    try std.testing.expectEqual(geometry.commitment_rows, main.coefficients.column_stride_words);
    try std.testing.expectEqual(try geometry.traceRowCount(), composition.coefficients.column_stride_words);
    try std.testing.expectEqual(
        preprocessed.evaluations.storage.address +
            preprocessed.evaluations.storage.len * @sizeOf(u32),
        main.evaluations.storage.address,
    );
    try std.testing.expectEqual(
        main.evaluations.storage.address +
            main.evaluations.storage.len * @sizeOf(u32),
        composition.evaluations.storage.address,
    );
}

const TestProvider = struct {
    prepared: *const plan_mod.PreparedPlan,

    pub fn slot(self: *const TestProvider, id: slots.SlotId) !Words {
        const geometry = self.prepared.logical.geometry;
        const rows = try geometry.traceRowCount();
        const committed = geometry.commitment_rows;
        const hashes = try sub(try mul(committed, 2), 1);
        const layers = @as(usize, geometry.commitment_log_rows) + 1;
        const words = switch (id) {
            slots.twiddles_forward, slots.twiddles_inverse => rows,
            slots.protocol_words, slots.statement_words, slots.composition_challenge => 4,
            slots.transcript_state,
            slots.transcript_input_snapshot,
            slots.transcript_boundary_snapshot,
            => 16,
            slots.transcript_output_snapshot => 8,
            slots.preprocessed_coefficients => 2 * committed,
            slots.main_coefficients => committed,
            slots.composition_coefficients => 8 * rows,
            slots.source_evaluations => 11 * committed,
            slots.preprocessed_log_sizes => 2,
            slots.main_log_sizes => 1,
            slots.composition_log_sizes => 8,
            slots.preprocessed_merkle_hashes,
            slots.main_merkle_hashes,
            slots.composition_merkle_hashes,
            => 8 * hashes,
            slots.preprocessed_merkle_layers,
            slots.main_merkle_layers,
            slots.composition_merkle_layers,
            => 4 * layers,
            slots.composition_coordinates => 4 * committed,
            slots.proof_bundle => self.prepared.proof.total_words,
            else => return error.ArenaSlotMissing,
        };
        return .{
            .address = 0x1000 + @as(usize, id) * 0x100000,
            .len = words,
            .owner = 7,
            .generation = 11,
        };
    }
};
