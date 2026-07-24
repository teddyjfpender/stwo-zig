//! Canonical host-to-resident initialization for one proof transaction.

const field = @import("../../../../backends/cuda/abi/field.zig");
const canonical_ingress = @import("../canonical_ingress.zig");
const plan_mod = @import("../plan.zig");
const slots = @import("../slots.zig");
const bindings = @import("../resident_bindings/mod.zig");
const proof_assembly = @import("proof_assembly.zig");

/// Performs only ingress-authorized writes. Dynamic proof sections remain
/// zero until their owning GPU stage fills them.
pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    pack: *const canonical_ingress.Pack,
    views: *const bindings.Views,
) !void {
    if (views.proof.bundle.len != prepared.proof.total_words or
        views.transcript.static_inputs.len !=
            canonical_ingress.transcript_static_words)
    {
        return error.InvalidKernelDescriptor;
    }
    try proof_assembly.validateLayout(prepared, views);

    try transaction.zeroResidentSlice(
        u32,
        .ingress,
        slots.proof_bundle,
        0,
        views.proof.bundle.len,
    );
    try transaction.uploadResidentSlice(
        u32,
        slots.proof_bundle,
        0,
        prepared.proof.static_header,
    );

    try transaction.upload(
        u32,
        slots.twiddles_forward,
        pack.forwardTwiddleWords(),
    );
    try transaction.upload(
        u32,
        slots.twiddles_inverse,
        pack.inverseTwiddleWords(),
    );
    try transaction.upload(
        u32,
        slots.transcript_static_inputs,
        &pack.transcript_static,
    );

    try transaction.upload(
        u32,
        slots.coefficient_log_sizes,
        pack.coefficient_log_sizes,
    );
    try uploadTraceLayers(transaction, prepared);
    try transaction.upload(
        u32,
        slots.constraint_denominator_inverses,
        &pack.circle.composition_denominator_inverses,
    );

    try transaction.upload(
        field.CirclePointBaseField,
        slots.oods_offset_points,
        pack.oods_offset_points,
    );
    try transaction.upload(
        u32,
        slots.oods_fold_counts,
        pack.oods_fold_counts,
    );
    try transaction.upload(
        u32,
        slots.oods_output_indices,
        pack.oods_output_indices,
    );

    try uploadQuotientTopology(transaction, prepared);
    try uploadFriLayers(transaction, prepared);
    try uploadDecommitTopology(transaction, prepared);
}

pub fn configSource(
    views: *const bindings.Views,
) !@TypeOf(views.transcript.static_inputs) {
    return views.transcript.static_inputs.sub(
        0,
        canonical_ingress.transcript_config_words,
    );
}

pub fn emptyRootSource(
    views: *const bindings.Views,
) !@TypeOf(views.transcript.static_inputs) {
    return views.transcript.static_inputs.sub(
        canonical_ingress.transcript_config_words,
        canonical_ingress.transcript_empty_root_words,
    );
}

pub fn statementSource(
    views: *const bindings.Views,
) !@TypeOf(views.transcript.static_inputs) {
    return views.transcript.static_inputs.sub(
        canonical_ingress.transcript_config_words +
            canonical_ingress.transcript_empty_root_words,
        canonical_ingress.transcript_statement_words,
    );
}

fn uploadTraceLayers(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    const main = prepared.decommit.trace_trees[0];
    const composition = prepared.decommit.trace_trees[1];
    try transaction.upload(
        field.MerkleLayerDescriptor,
        slots.main_merkle_layers,
        retainedLayers(prepared, main.retained_layer_offset, main.retained_layer_count),
    );
    try transaction.upload(
        field.MerkleLayerDescriptor,
        slots.composition_merkle_layers,
        retainedLayers(
            prepared,
            composition.retained_layer_offset,
            composition.retained_layer_count,
        ),
    );
}

fn uploadQuotientTopology(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    const topology = prepared.quotient;
    try transaction.upload(
        @TypeOf(topology.prepared_terms[0]),
        slots.quotient_prepared_terms,
        topology.prepared_terms,
    );
    try transaction.upload(
        u32,
        slots.quotient_group_offsets,
        topology.group_offsets,
    );
    try transaction.upload(
        u32,
        slots.quotient_group_term_indices,
        topology.group_term_indices,
    );
    try transaction.upload(
        @TypeOf(topology.batch_terms[0]),
        slots.quotient_batch_terms,
        topology.batch_terms,
    );
    try transaction.upload(
        u32,
        slots.quotient_group_log_sizes,
        topology.group_log_sizes,
    );
    try transaction.upload(
        u32,
        slots.quotient_partial_log_sizes,
        topology.partial_log_sizes,
    );
}

fn uploadFriLayers(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    for (prepared.fri.layers, 0..) |layer, index| {
        const begin = layer.retained_layer_offset;
        const end = begin + layer.retained_layer_count;
        try transaction.upload(
            field.MerkleLayerDescriptor,
            slots.friMerkleLayers(index),
            prepared.fri.retained_layers[begin..end],
        );
    }
}

fn uploadDecommitTopology(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
) !void {
    const geometry = prepared.logical.geometry;
    const column_logs = prepared.decommit.column_log_sizes;
    if (column_logs.len != geometry.sampled_value_count)
        return error.InvalidKernelDescriptor;
    try transaction.upload(
        u32,
        slots.decommit_sparse_level_offsets,
        &.{0},
    );
    try transaction.upload(
        u32,
        slots.main_column_log_sizes,
        column_logs[0..geometry.main_columns],
    );
    try transaction.upload(
        u32,
        slots.composition_column_log_sizes,
        column_logs[geometry.main_columns..],
    );
}

fn retainedLayers(
    prepared: *const plan_mod.PreparedPlan,
    offset: usize,
    count: usize,
) []const field.MerkleLayerDescriptor {
    return prepared.decommit.retained_layers[offset..][0..count];
}

test "ingress writes one zeroed bundle and canonical sealed inputs only" {
    const std = @import("std");
    const arena = @import("../../../../backends/cuda/runtime/arena.zig");
    const support = @import("trace/test_support.zig");

    const Record = struct {
        id: arena.SlotId,
        first: usize,
        count: usize,
        element_bytes: usize,
    };
    const FakeTransaction = struct {
        records: [96]Record = undefined,
        record_count: usize = 0,
        zero_count: usize = 0,
        zero_words: usize = 0,

        fn append(
            self: *@This(),
            comptime F: type,
            id: arena.SlotId,
            first: usize,
            count_value: usize,
        ) !void {
            if (self.record_count == self.records.len)
                return error.TooManyUploads;
            self.records[self.record_count] = .{
                .id = id,
                .first = first,
                .count = count_value,
                .element_bytes = @sizeOf(F),
            };
            self.record_count += 1;
        }

        pub fn zeroResidentSlice(
            self: *@This(),
            comptime F: type,
            stage: anytype,
            id: arena.SlotId,
            first: usize,
            count_value: usize,
        ) !void {
            try std.testing.expectEqual(@as(usize, @sizeOf(u32)), @sizeOf(F));
            try std.testing.expectEqual(.ingress, stage);
            try std.testing.expectEqual(slots.proof_bundle, id);
            try std.testing.expectEqual(@as(usize, 0), first);
            self.zero_count += 1;
            self.zero_words = count_value;
        }

        pub fn uploadResidentSlice(
            self: *@This(),
            comptime F: type,
            id: arena.SlotId,
            first: usize,
            values: []const F,
        ) !void {
            try self.append(F, id, first, values.len);
        }

        pub fn upload(
            self: *@This(),
            comptime F: type,
            id: arena.SlotId,
            values: []const F,
        ) !void {
            try self.append(F, id, 0, values.len);
        }
    };

    const allocator = std.testing.allocator;
    const geometry = try support.geometry(5, 8);
    var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    var pack = try canonical_ingress.Pack.init(allocator, geometry);
    defer pack.deinit(allocator);
    const provider = support.Provider{ .prepared = &prepared };
    const views = try bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{};

    try run(&transaction, &prepared, &pack, &views);
    try std.testing.expectEqual(@as(usize, 1), transaction.zero_count);
    try std.testing.expectEqual(
        prepared.proof.total_words,
        transaction.zero_words,
    );
    try std.testing.expect(transaction.record_count > 20);
    try std.testing.expectEqual(slots.proof_bundle, transaction.records[0].id);
    try std.testing.expectEqual(
        prepared.proof.static_header.len,
        transaction.records[0].count,
    );

    var static_uploads: usize = 0;
    var proof_uploads: usize = 0;
    for (transaction.records[0..transaction.record_count]) |record| {
        if (record.id == slots.transcript_static_inputs) {
            static_uploads += 1;
            try std.testing.expectEqual(
                canonical_ingress.transcript_static_words,
                record.count,
            );
        }
        if (record.id == slots.proof_bundle) proof_uploads += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), static_uploads);
    try std.testing.expectEqual(@as(usize, 1), proof_uploads);
}
