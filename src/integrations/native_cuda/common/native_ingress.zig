//! Shared canonical host-to-resident initialization for Native CUDA AIRs.

const field = @import(
    "../../../backends/cuda/abi/field.zig",
);
const proof_assembly = @import("proof_assembly.zig");

pub fn ExecutorFor(
    comptime geometry_mod: type,
    comptime plan_mod: type,
    comptime canonical: type,
    comptime slots: type,
) type {
    return struct {
        pub fn run(
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
            pack: *const canonical.Pack,
            views: anytype,
        ) !void {
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
                slots.protocol_words,
                &pack.protocol_words,
            );
            try transaction.upload(
                u32,
                slots.statement_words,
                &pack.statement_words,
            );
            try uploadColumnLogs(transaction, pack);
            try uploadTraceLayers(transaction, prepared);
            try transaction.upload(
                field.CirclePointBaseField,
                slots.oods_offset_points,
                &pack.oods_offset_points,
            );
            try transaction.upload(
                u32,
                slots.oods_fold_counts,
                &pack.oods_fold_counts,
            );
            try transaction.upload(
                u32,
                slots.oods_output_indices,
                &pack.oods_output_indices,
            );
            try uploadQuotientTopology(transaction, prepared);
            try uploadFriLayers(transaction, prepared);
            try transaction.upload(
                u32,
                slots.decommit_sparse_level_offsets,
                &.{0},
            );
        }

        fn uploadColumnLogs(
            transaction: anytype,
            pack: *const canonical.Pack,
        ) !void {
            const logs = &pack.coefficient_log_sizes;
            const preprocessed_end = geometry_mod.preprocessed_columns;
            const main_end = preprocessed_end + geometry_mod.main_columns;
            const composition_end = main_end + geometry_mod.composition_columns;
            try transaction.upload(
                u32,
                slots.preprocessed_log_sizes,
                logs[0..preprocessed_end],
            );
            try transaction.upload(
                u32,
                slots.main_log_sizes,
                logs[preprocessed_end..main_end],
            );
            try transaction.upload(
                u32,
                slots.composition_log_sizes,
                logs[main_end..composition_end],
            );
        }

        fn uploadTraceLayers(
            transaction: anytype,
            prepared: *const plan_mod.PreparedPlan,
        ) !void {
            const ids = [_]@TypeOf(slots.preprocessed_merkle_layers){
                slots.preprocessed_merkle_layers,
                slots.main_merkle_layers,
                slots.composition_merkle_layers,
            };
            if (prepared.decommit.trace_trees.len != ids.len)
                return error.InvalidKernelDescriptor;
            for (prepared.decommit.trace_trees, ids) |tree, id| {
                const begin = tree.retained_layer_offset;
                const end = begin + tree.retained_layer_count;
                try transaction.upload(
                    field.MerkleLayerDescriptor,
                    id,
                    prepared.decommit.retained_layers[begin..end],
                );
            }
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
    };
}
