//! PoW, decommitment, and terminal resident bindings for Cairo CUDA.

const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("stwo_cuda_backend").abi.field;
const shared_proof = @import("stwo_native_cuda_integration").common.resident_proof_binding;
const shared_bundle = @import("stwo_native_cuda_integration").common.proof_bundle;
const shared_views = @import("stwo_native_cuda_integration").common.resident_views;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const resident_plan = @import("resident_plan.zig");
const slots = @import("pcs_slot_binding.zig");
const terminal_bundle = @import("terminal_bundle.zig");

pub fn bindPow(
    provider: anytype,
    plan: *const resident_plan.Plan,
    ordinal: u32,
) !shared_views.Pow {
    return .{
        .prefix_digest = try slots.exactWords(
            provider,
            plan,
            .pow_prefix,
            ordinal,
            8,
        ),
        .best_nonce = try (try slots.exactWords(
            provider,
            plan,
            .pow_best_nonce,
            ordinal,
            2,
        )).cast(u64),
        .completed_blocks = try slots.exactWords(
            provider,
            plan,
            .pow_completed_blocks,
            ordinal,
            1,
        ),
        .transcript_nonce = try slots.exactWords(
            provider,
            plan,
            .pow_transcript_nonce,
            ordinal,
            2,
        ),
    };
}

pub fn bindDecommit(
    provider: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !shared_views.Decommit {
    const counts = try slots.exactWords(
        provider,
        plan,
        .decommit_counts,
        0,
        5,
    );
    const logs = try slots.exact(
        provider,
        plan,
        .decommit_column_logs,
        0,
    );
    var by_role: [4]slots.Words = undefined;
    var cursor: usize = 0;
    for (program.commitments) |tree| {
        const role_index = commitmentRoleIndex(tree.role) orelse
            return error.InvalidKernelDescriptor;
        by_role[role_index] = try logs.sub(cursor, tree.column_count);
        cursor = try slots.add(cursor, tree.column_count);
    }
    if (cursor != logs.len) return error.InvalidKernelDescriptor;
    return .{
        .raw_queries = try slots.exactWords(
            provider,
            plan,
            .decommit_raw_queries,
            0,
            protocol.query_count,
        ),
        .unique_queries = try slots.exactWords(
            provider,
            plan,
            .decommit_unique_queries,
            0,
            protocol.query_count,
        ),
        .mapped_queries = try slots.exactWords(
            provider,
            plan,
            .decommit_mapped_queries,
            0,
            protocol.query_count,
        ),
        .walk_queries = try slots.exact(
            provider,
            plan,
            .decommit_walk_queries,
            0,
        ),
        .walk_scratch = try slots.exact(
            provider,
            plan,
            .decommit_walk_scratch,
            0,
        ),
        .leaf_indices = try slots.exact(
            provider,
            plan,
            .decommit_leaf_indices,
            0,
        ),
        .expanded_positions = try slots.exact(
            provider,
            plan,
            .decommit_expanded_positions,
            0,
        ),
        .sparse_indices = try slots.exact(
            provider,
            plan,
            .decommit_sparse_indices,
            0,
        ),
        .sparse_hashes = try (try slots.exact(
            provider,
            plan,
            .decommit_sparse_hashes,
            0,
        )).cast(field.Blake2sHash),
        .counts = .{
            .unique = try counts.sub(0, 1),
            .mapped_or_tree = try counts.sub(1, 1),
            .walk = try counts.sub(2, 1),
            .expanded = try counts.sub(3, 1),
            .leaf_or_sparse = try counts.sub(4, 1),
        },
        .sparse_level_offsets = try slots.exact(
            provider,
            plan,
            .decommit_level_offsets,
            0,
        ),
        .sparse_level_counts = try slots.exact(
            provider,
            plan,
            .decommit_level_counts,
            0,
        ),
        .preprocessed_column_log_sizes = by_role[0],
        .main_column_log_sizes = by_role[1],
        .interaction_column_log_sizes = by_role[2],
        .composition_column_log_sizes = by_role[3],
    };
}

pub fn bindProof(
    provider: anytype,
    plan: *const resident_plan.Plan,
) !shared_views.Proof {
    const proof_slot = plan.slot(.terminal_bundle, 0) orelse
        return error.InvalidKernelDescriptor;
    const prepared = struct {
        proof: terminal_bundle.Bundle,
    }{ .proof = plan.terminal_bundle };
    return shared_proof.bindAt(
        shared_bundle,
        provider,
        proof_slot.id,
        0,
        prepared,
    );
}

fn commitmentRoleIndex(role: proof_ir.CommitmentRole) ?usize {
    return switch (role) {
        .preprocessed => 0,
        .main => 1,
        .interaction => 2,
        .composition => 3,
        .fri => null,
    };
}
