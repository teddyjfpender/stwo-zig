//! Canonical detached-parent typed AIR roster. Production, verification and
//! backend export consume these exact admitted owners. The independent legacy
//! selection comparison lives in the integration preparation tests.
const Entry = @import("universal_catalog_entry.zig").Entry;

pub const LOGICAL_ROWS = [29]Entry{
    .{ .Air = @import("stwo_riscv_air_lang").framework_control, .row = .control },
    .{ .Air = @import("transcript_air.zig"), .row = .transcript_air },
    .{ .Air = @import("transcript_binding.zig"), .row = .transcript_binding },
    .{ .Air = @import("transcript_state.zig"), .row = .transcript_state },
    .{ .Air = @import("transcript_word.zig"), .row = .transcript_word },
    .{ .Air = @import("transcript_payload.zig"), .row = .transcript_payload },
    .{ .Air = @import("pow_check.zig"), .row = .pow_check },
    .{ .Air = @import("pow_frame.zig"), .row = .pow_frame },
    .{ .Air = @import("relation_challenge.zig"), .row = .relation_challenge },
    .{ .Air = @import("verifier_randomness.zig"), .row = .verifier_randomness },
    .{ .Air = @import("field_statement_word.zig"), .row = .statement_input },
    .{ .Air = @import("detached_graph_input.zig"), .row = .statement_semantics_input },
    .{ .Air = @import("detached_poseidon_graph.zig"), .row = .vm_public_claim_input },
    .{ .Air = @import("fixed_wire.zig"), .row = .vm_public_claim_hash },
    .{ .Air = @import("stwo_riscv_air_lang").framework_detached_opening_accumulate4, .row = .vm_public_io_hash },
    .{ .Air = @import("query_bits.zig"), .row = .query_bits },
    .{ .Air = @import("query_mapping.zig"), .row = .query_mapping },
    .{ .Air = @import("merkle_root.zig"), .row = .merkle_root },
    .{ .Air = @import("trace_merkle.zig"), .row = .trace_merkle },
    .{ .Air = @import("pcs_deep_input.zig"), .row = .pcs_deep_input },
    .{ .Air = @import("fri_merkle_leaf.zig"), .row = .fri_merkle_leaf },
    .{ .Air = @import("fri_merkle_node.zig"), .row = .fri_merkle_node },
    .{ .Air = @import("fri_merkle_anchor.zig"), .row = .fri_merkle_anchor },
    .{ .Air = @import("fri_verifier_control.zig"), .row = .fri_verifier_control },
    .{ .Air = @import("fri_verifier_input.zig"), .row = .fri_verifier_input },
    .{ .Air = @import("stwo_riscv_air_lang").framework_qm31_mul_add, .row = .qm31_mul },
    .{ .Air = @import("stwo_riscv_air_lang").framework_qm31_inv, .row = .qm31_inv, .requires_location = true },
    .{ .Air = @import("stwo_riscv_air_lang").framework_linear_ops, .row = .linear_ops, .requires_location = true },
    .{ .Air = @import("merkle_path.zig"), .row = .merkle_path },
};
