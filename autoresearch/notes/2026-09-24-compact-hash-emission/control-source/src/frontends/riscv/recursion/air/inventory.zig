//! Explicit inventory of recursion-local AIR admitted through the typed compiler.
//!
//! The inventory is intentionally separate from the 36-component target map:
//! an entry here means executable Zig substrate exists, not that a universal
//! recursive verifier or its relation closure has been completed.

const std = @import("std");
const static_profile = @import("../../air/lang/static_profile.zig");
const control = @import("control.zig");
const fri_merkle_anchor = @import("fri_merkle_anchor.zig");
const fri_merkle_leaf = @import("fri_merkle_leaf.zig");
const fri_merkle_node = @import("fri_merkle_node.zig");
const fri_verifier_control = @import("fri_verifier_control.zig");
const fri_verifier_input = @import("fri_verifier_input.zig");
const linear_ops = @import("linear_ops.zig");
const merkle_path = @import("merkle_path.zig");
const merkle_root = @import("merkle_root.zig");
const pcs_deep_input = @import("pcs_deep_input.zig");
const pow_check = @import("pow_check.zig");
const pow_frame = @import("pow_frame.zig");
const qm31_inv = @import("qm31_inv.zig");
const qm31_mul = @import("qm31_mul.zig");
const qm31_mul_full = @import("qm31_mul_full.zig");
const query_bits = @import("query_bits.zig");
const query_mapping = @import("query_mapping.zig");
const relation_challenge = @import("relation_challenge.zig");
const statement_input = @import("statement_input.zig");
const statement_semantics_input = @import("statement_semantics_input.zig");
const trace_merkle = @import("trace_merkle.zig");
const transcript_air = @import("transcript_air.zig");
const transcript_binding = @import("transcript_binding.zig");
const transcript_payload = @import("transcript_payload.zig");
const transcript_state = @import("transcript_state.zig");
const transcript_word = @import("transcript_word.zig");
const vm_air_composition_control = @import("vm_air_composition_control.zig").Air;
const vm_air_composition_input = @import("vm_air_composition_input.zig");
const vm_public_claim_hash = @import("vm_public_claim_hash.zig");
const vm_public_claim_input = @import("vm_public_claim_input.zig");
const vm_public_claim_semantics_input = @import("vm_public_claim_semantics_input.zig");
const vm_public_io_hash = @import("vm_public_io_hash.zig");
const vm_public_logup_control = @import("vm_public_logup_control.zig").Air;
const vm_public_logup_input = @import("vm_public_logup_input.zig");
const verifier_randomness = @import("verifier_randomness.zig");

pub const Component = enum(u8) {
    qm31_mul_standalone = 0,
    qm31_mul_full = 1,
    qm31_inv_full = 2,
    linear_ops_full = 3,
    statement_input = 4,
    statement_semantics_input = 5,
    vm_public_claim_input = 6,
    vm_public_claim_semantics_input = 7,
    vm_public_logup_input = 8,
    vm_public_logup_control = 9,
    vm_air_composition_input = 10,
    vm_air_composition_control = 11,
    control = 12,
    query_bits = 13,
    query_mapping = 14,
    merkle_root = 15,
    trace_merkle = 16,
    pcs_deep_input = 17,
    fri_merkle_leaf = 18,
    fri_merkle_node = 19,
    fri_merkle_anchor = 20,
    fri_verifier_control = 21,
    fri_verifier_input = 22,
    merkle_path = 23,
    relation_challenge = 24,
    pow_check = 25,
    pow_frame = 26,
    verifier_randomness = 27,
    transcript_word = 28,
    transcript_binding = 29,
    transcript_state = 30,
    transcript_payload = 31,
    transcript_air = 32,
    vm_public_claim_hash = 33,
    vm_public_io_hash = 34,
};

pub const COMPONENT_COUNT: usize = @typeInfo(Component).@"enum".fields.len;

pub const Status = enum(u8) {
    /// Arithmetic identities and standalone witness rows only. Universal
    /// schedule preprocessing and relation wiring remain outside this entry.
    typed_substrate = 1,
    /// Exact reference logical geometry, schedule constraints, typed relation
    /// effects, direct witness writers, and authenticated interaction plan.
    /// Concrete universal-recursion component and transcript integration remain
    /// outside this status.
    typed_logical_component = 2,
};

pub const Authorship = enum(u8) {
    typed_ir = 1,
};

pub const Descriptor = struct {
    component: Component,
    /// Exact row in the pinned universal-recursion component roster. Arithmetic
    /// substrate that is shared by several roster rows has no unique row.
    universal_row: ?u8,
    stable_name: []const u8,
    owner: []const u8,
    status: Status,
    authorship: Authorship,
    physical_main_columns: u32,
    constraint_roots: u32,
    relation_events: u32,
    maximum_constraint_degree: u32,
    semantic_digest: [32]u8,
};

pub const DESCRIPTORS = [COMPONENT_COUNT]Descriptor{
    .{
        .component = .qm31_mul_standalone,
        .universal_row = null,
        .stable_name = "recursion.qm31_mul.standalone.v1",
        .owner = "recursion/air/qm31_mul.zig",
        .status = .typed_substrate,
        .authorship = .typed_ir,
        .physical_main_columns = qm31_mul.PHYSICAL_COLUMN_COUNT,
        .constraint_roots = qm31_mul.CONSTRAINT_COUNT,
        .relation_events = 0,
        .maximum_constraint_degree = qm31_mul.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = qm31_mul.SEMANTIC_DIGEST,
    },
    .{
        .component = .qm31_mul_full,
        .universal_row = 30,
        .stable_name = "recursion.qm31_mul.full.v1",
        .owner = "recursion/air/qm31_mul_full.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = qm31_mul_full.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = qm31_mul_full.DIRECT_CONSTRAINT_COUNT,
        .relation_events = qm31_mul_full.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = qm31_mul_full.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = qm31_mul_full.SEMANTIC_DIGEST,
    },
    .{
        .component = .qm31_inv_full,
        .universal_row = 31,
        .stable_name = "recursion.qm31_inv.full.v1",
        .owner = "recursion/air/qm31_inv.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = qm31_inv.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = qm31_inv.DIRECT_CONSTRAINT_COUNT,
        .relation_events = qm31_inv.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = qm31_inv.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = qm31_inv.SEMANTIC_DIGEST,
    },
    .{
        .component = .linear_ops_full,
        .universal_row = 32,
        .stable_name = "recursion.linear_ops.full.v1",
        .owner = "recursion/air/linear_ops.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = linear_ops.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = linear_ops.DIRECT_CONSTRAINT_COUNT,
        .relation_events = linear_ops.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = linear_ops.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = linear_ops.SEMANTIC_DIGEST,
    },
    .{
        .component = .statement_input,
        .universal_row = 10,
        .stable_name = statement_input.STABLE_NAME,
        .owner = "recursion/air/statement_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = statement_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = statement_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = statement_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = statement_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = statement_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .statement_semantics_input,
        .universal_row = 11,
        .stable_name = statement_semantics_input.STABLE_NAME,
        .owner = "recursion/air/statement_semantics_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = statement_semantics_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = statement_semantics_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = statement_semantics_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = statement_semantics_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = statement_semantics_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_public_claim_input,
        .universal_row = 12,
        .stable_name = vm_public_claim_input.STABLE_NAME,
        .owner = "recursion/air/vm_public_claim_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_public_claim_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_public_claim_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_public_claim_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_public_claim_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_public_claim_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_public_claim_semantics_input,
        .universal_row = 15,
        .stable_name = vm_public_claim_semantics_input.STABLE_NAME,
        .owner = "recursion/air/vm_public_claim_semantics_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_public_claim_semantics_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_public_claim_semantics_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_public_claim_semantics_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_public_claim_semantics_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_public_claim_semantics_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_public_logup_input,
        .universal_row = 16,
        .stable_name = vm_public_logup_input.STABLE_NAME,
        .owner = "recursion/air/vm_public_logup_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_public_logup_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_public_logup_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_public_logup_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_public_logup_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_public_logup_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_public_logup_control,
        .universal_row = 17,
        .stable_name = vm_public_logup_control.STABLE_NAME,
        .owner = "recursion/air/vm_public_logup_control.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_public_logup_control.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_public_logup_control.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_public_logup_control.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_public_logup_control.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_public_logup_control.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_air_composition_input,
        .universal_row = 18,
        .stable_name = vm_air_composition_input.STABLE_NAME,
        .owner = "recursion/air/vm_air_composition_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_air_composition_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_air_composition_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_air_composition_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_air_composition_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_air_composition_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_air_composition_control,
        .universal_row = 19,
        .stable_name = vm_air_composition_control.STABLE_NAME,
        .owner = "recursion/air/vm_air_composition_control.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_air_composition_control.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_air_composition_control.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_air_composition_control.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_air_composition_control.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_air_composition_control.SEMANTIC_DIGEST,
    },
    .{
        .component = .control,
        .universal_row = 0,
        .stable_name = control.STABLE_NAME,
        .owner = "recursion/air/control.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = control.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = control.DIRECT_CONSTRAINT_COUNT,
        .relation_events = control.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = control.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = control.SEMANTIC_DIGEST,
    },
    .{
        .component = .query_bits,
        .universal_row = 20,
        .stable_name = query_bits.STABLE_NAME,
        .owner = "recursion/air/query_bits.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = query_bits.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = query_bits.DIRECT_CONSTRAINT_COUNT,
        .relation_events = query_bits.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = query_bits.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = query_bits.SEMANTIC_DIGEST,
    },
    .{
        .component = .query_mapping,
        .universal_row = 21,
        .stable_name = query_mapping.STABLE_NAME,
        .owner = "recursion/air/query_mapping.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = query_mapping.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = query_mapping.DIRECT_CONSTRAINT_COUNT,
        .relation_events = query_mapping.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = query_mapping.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = query_mapping.SEMANTIC_DIGEST,
    },
    .{
        .component = .merkle_root,
        .universal_row = 22,
        .stable_name = merkle_root.STABLE_NAME,
        .owner = "recursion/air/merkle_root.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = merkle_root.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = merkle_root.DIRECT_CONSTRAINT_COUNT,
        .relation_events = merkle_root.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = merkle_root.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = merkle_root.SEMANTIC_DIGEST,
    },
    .{
        .component = .trace_merkle,
        .universal_row = 23,
        .stable_name = trace_merkle.STABLE_NAME,
        .owner = "recursion/air/trace_merkle.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = trace_merkle.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = trace_merkle.DIRECT_CONSTRAINT_COUNT,
        .relation_events = trace_merkle.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = trace_merkle.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = trace_merkle.SEMANTIC_DIGEST,
    },
    .{
        .component = .pcs_deep_input,
        .universal_row = 24,
        .stable_name = pcs_deep_input.STABLE_NAME,
        .owner = "recursion/air/pcs_deep_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = pcs_deep_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = pcs_deep_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = pcs_deep_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = pcs_deep_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = pcs_deep_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .fri_merkle_leaf,
        .universal_row = 25,
        .stable_name = fri_merkle_leaf.STABLE_NAME,
        .owner = "recursion/air/fri_merkle_leaf.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = fri_merkle_leaf.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = fri_merkle_leaf.DIRECT_CONSTRAINT_COUNT,
        .relation_events = fri_merkle_leaf.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = fri_merkle_leaf.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = fri_merkle_leaf.SEMANTIC_DIGEST,
    },
    .{
        .component = .fri_merkle_node,
        .universal_row = 26,
        .stable_name = fri_merkle_node.STABLE_NAME,
        .owner = "recursion/air/fri_merkle_node.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = fri_merkle_node.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = fri_merkle_node.DIRECT_CONSTRAINT_COUNT,
        .relation_events = fri_merkle_node.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = fri_merkle_node.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = fri_merkle_node.SEMANTIC_DIGEST,
    },
    .{
        .component = .fri_merkle_anchor,
        .universal_row = 27,
        .stable_name = fri_merkle_anchor.STABLE_NAME,
        .owner = "recursion/air/fri_merkle_anchor.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = fri_merkle_anchor.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = fri_merkle_anchor.DIRECT_CONSTRAINT_COUNT,
        .relation_events = fri_merkle_anchor.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = fri_merkle_anchor.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = fri_merkle_anchor.SEMANTIC_DIGEST,
    },
    .{
        .component = .fri_verifier_control,
        .universal_row = 28,
        .stable_name = fri_verifier_control.STABLE_NAME,
        .owner = "recursion/air/fri_verifier_control.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = fri_verifier_control.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = fri_verifier_control.DIRECT_CONSTRAINT_COUNT,
        .relation_events = fri_verifier_control.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = fri_verifier_control.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = fri_verifier_control.SEMANTIC_DIGEST,
    },
    .{
        .component = .fri_verifier_input,
        .universal_row = 29,
        .stable_name = fri_verifier_input.STABLE_NAME,
        .owner = "recursion/air/fri_verifier_input.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = fri_verifier_input.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = fri_verifier_input.DIRECT_CONSTRAINT_COUNT,
        .relation_events = fri_verifier_input.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = fri_verifier_input.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = fri_verifier_input.SEMANTIC_DIGEST,
    },
    .{
        .component = .merkle_path,
        .universal_row = 33,
        .stable_name = merkle_path.STABLE_NAME,
        .owner = "recursion/air/merkle_path.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = merkle_path.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = merkle_path.DIRECT_CONSTRAINT_COUNT,
        .relation_events = merkle_path.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = merkle_path.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = merkle_path.SEMANTIC_DIGEST,
    },
    .{
        .component = .relation_challenge,
        .universal_row = 8,
        .stable_name = relation_challenge.STABLE_NAME,
        .owner = "recursion/air/relation_challenge.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = relation_challenge.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = relation_challenge.DIRECT_CONSTRAINT_COUNT,
        .relation_events = relation_challenge.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = relation_challenge.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = relation_challenge.SEMANTIC_DIGEST,
    },
    .{
        .component = .pow_check,
        .universal_row = 6,
        .stable_name = pow_check.STABLE_NAME,
        .owner = "recursion/air/pow_check.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = pow_check.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = pow_check.DIRECT_CONSTRAINT_COUNT,
        .relation_events = pow_check.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = pow_check.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = pow_check.SEMANTIC_DIGEST,
    },
    .{
        .component = .pow_frame,
        .universal_row = 7,
        .stable_name = pow_frame.STABLE_NAME,
        .owner = "recursion/air/pow_frame.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = pow_frame.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = pow_frame.DIRECT_CONSTRAINT_COUNT,
        .relation_events = pow_frame.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = pow_frame.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = pow_frame.SEMANTIC_DIGEST,
    },
    .{
        .component = .verifier_randomness,
        .universal_row = 9,
        .stable_name = verifier_randomness.STABLE_NAME,
        .owner = "recursion/air/verifier_randomness.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = verifier_randomness.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = verifier_randomness.DIRECT_CONSTRAINT_COUNT,
        .relation_events = verifier_randomness.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = verifier_randomness.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = verifier_randomness.SEMANTIC_DIGEST,
    },
    .{
        .component = .transcript_word,
        .universal_row = 4,
        .stable_name = transcript_word.STABLE_NAME,
        .owner = "recursion/air/transcript_word.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = transcript_word.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = transcript_word.DIRECT_CONSTRAINT_COUNT,
        .relation_events = transcript_word.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = transcript_word.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = transcript_word.SEMANTIC_DIGEST,
    },
    .{
        .component = .transcript_binding,
        .universal_row = 2,
        .stable_name = transcript_binding.STABLE_NAME,
        .owner = "recursion/air/transcript_binding.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = transcript_binding.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = transcript_binding.DIRECT_CONSTRAINT_COUNT,
        .relation_events = transcript_binding.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = transcript_binding.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = transcript_binding.SEMANTIC_DIGEST,
    },
    .{
        .component = .transcript_state,
        .universal_row = 3,
        .stable_name = transcript_state.STABLE_NAME,
        .owner = "recursion/air/transcript_state.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = transcript_state.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = transcript_state.DIRECT_CONSTRAINT_COUNT,
        .relation_events = transcript_state.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = transcript_state.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = transcript_state.SEMANTIC_DIGEST,
    },
    .{
        .component = .transcript_payload,
        .universal_row = 5,
        .stable_name = transcript_payload.STABLE_NAME,
        .owner = "recursion/air/transcript_payload.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = transcript_payload.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = transcript_payload.DIRECT_CONSTRAINT_COUNT,
        .relation_events = transcript_payload.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = transcript_payload.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = transcript_payload.SEMANTIC_DIGEST,
    },
    .{
        .component = .transcript_air,
        .universal_row = 1,
        .stable_name = transcript_air.STABLE_NAME,
        .owner = "recursion/air/transcript_air.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = transcript_air.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = transcript_air.DIRECT_CONSTRAINT_COUNT,
        .relation_events = transcript_air.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = transcript_air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = transcript_air.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_public_claim_hash,
        .universal_row = 13,
        .stable_name = vm_public_claim_hash.STABLE_NAME,
        .owner = "recursion/air/vm_public_claim_hash.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_public_claim_hash.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_public_claim_hash.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_public_claim_hash.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_public_claim_hash.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_public_claim_hash.SEMANTIC_DIGEST,
    },
    .{
        .component = .vm_public_io_hash,
        .universal_row = 14,
        .stable_name = vm_public_io_hash.STABLE_NAME,
        .owner = "recursion/air/vm_public_io_hash.zig",
        .status = .typed_logical_component,
        .authorship = .typed_ir,
        .physical_main_columns = vm_public_io_hash.PHYSICAL_MAIN_COLUMN_COUNT,
        .constraint_roots = vm_public_io_hash.DIRECT_CONSTRAINT_COUNT,
        .relation_events = vm_public_io_hash.RELATION_EVENT_COUNT,
        .maximum_constraint_degree = vm_public_io_hash.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = vm_public_io_hash.SEMANTIC_DIGEST,
    },
};

comptime {
    for (DESCRIPTORS, 0..) |descriptor, index| {
        if (@intFromEnum(descriptor.component) != index)
            @compileError("recursion typed-AIR inventory is not canonical");
    }
}

pub fn collectProfile(
    allocator: std.mem.Allocator,
    component: Component,
) !static_profile.Profile {
    return switch (component) {
        .qm31_mul_standalone => blk: {
            var definition = try qm31_mul.build(allocator, .generated);
            defer definition.deinit();
            break :blk try static_profile.collect(allocator, &definition.arena, .{
                .physical_main_columns = qm31_mul.PHYSICAL_COLUMN_COUNT,
            });
        },
        .qm31_mul_full => blk: {
            var definition = try qm31_mul_full.build(allocator, .generated);
            defer definition.deinit();
            break :blk try static_profile.collect(allocator, &definition.arena, .{
                .physical_main_columns = qm31_mul_full.PHYSICAL_MAIN_COLUMN_COUNT,
                .lookup_layout = .{
                    .batch_size = qm31_mul_full.LOOKUP_BATCH_SIZE,
                    .interaction_coordinates_per_batch = 4,
                },
            });
        },
        .qm31_inv_full => blk: {
            var definition = try qm31_inv.build(allocator, .generated);
            defer definition.deinit();
            break :blk try static_profile.collect(allocator, &definition.arena, .{
                .physical_main_columns = qm31_inv.PHYSICAL_MAIN_COLUMN_COUNT,
                .lookup_layout = .{
                    .batch_size = qm31_inv.LOOKUP_BATCH_SIZE,
                    .interaction_coordinates_per_batch = 4,
                },
            });
        },
        .linear_ops_full => blk: {
            var definition = try linear_ops.build(allocator, .generated);
            defer definition.deinit();
            break :blk try static_profile.collect(allocator, &definition.arena, .{
                .physical_main_columns = linear_ops.PHYSICAL_MAIN_COLUMN_COUNT,
                .lookup_layout = .{
                    .batch_size = linear_ops.LOOKUP_BATCH_SIZE,
                    .interaction_coordinates_per_batch = 4,
                },
            });
        },
        .control => try collectLogicalProfile(allocator, control),
        .query_bits => try collectLogicalProfile(allocator, query_bits),
        .query_mapping => try collectLogicalProfile(allocator, query_mapping),
        .merkle_root => try collectLogicalProfile(allocator, merkle_root),
        .trace_merkle => try collectLogicalProfile(allocator, trace_merkle),
        .pcs_deep_input => try collectLogicalProfile(allocator, pcs_deep_input),
        .fri_merkle_leaf => try collectLogicalProfile(allocator, fri_merkle_leaf),
        .fri_merkle_node => try collectLogicalProfile(allocator, fri_merkle_node),
        .fri_merkle_anchor => try collectLogicalProfile(allocator, fri_merkle_anchor),
        .fri_verifier_control => try collectLogicalProfile(allocator, fri_verifier_control),
        .fri_verifier_input => try collectLogicalProfile(allocator, fri_verifier_input),
        .merkle_path => try collectLogicalProfile(allocator, merkle_path),
        .relation_challenge => try collectLogicalProfile(allocator, relation_challenge),
        .pow_check => try collectLogicalProfile(allocator, pow_check),
        .pow_frame => try collectLogicalProfile(allocator, pow_frame),
        .verifier_randomness => try collectLogicalProfile(allocator, verifier_randomness),
        .transcript_word => try collectLogicalProfile(allocator, transcript_word),
        .transcript_binding => try collectLogicalProfile(allocator, transcript_binding),
        .transcript_state => try collectLogicalProfile(allocator, transcript_state),
        .transcript_payload => try collectLogicalProfile(allocator, transcript_payload),
        .transcript_air => try collectLogicalProfile(allocator, transcript_air),
        .vm_public_claim_hash => try collectLogicalProfile(
            allocator,
            vm_public_claim_hash,
        ),
        .vm_public_io_hash => try collectLogicalProfile(
            allocator,
            vm_public_io_hash,
        ),
        .statement_input => try collectLogicalProfile(allocator, statement_input),
        .statement_semantics_input => try collectLogicalProfile(
            allocator,
            statement_semantics_input,
        ),
        .vm_public_claim_input => try collectLogicalProfile(
            allocator,
            vm_public_claim_input,
        ),
        .vm_public_claim_semantics_input => try collectLogicalProfile(
            allocator,
            vm_public_claim_semantics_input,
        ),
        .vm_public_logup_input => try collectLogicalProfile(
            allocator,
            vm_public_logup_input,
        ),
        .vm_public_logup_control => try collectLogicalProfile(
            allocator,
            vm_public_logup_control,
        ),
        .vm_air_composition_input => try collectLogicalProfile(
            allocator,
            vm_air_composition_input,
        ),
        .vm_air_composition_control => try collectLogicalProfile(
            allocator,
            vm_air_composition_control,
        ),
    };
}

fn collectLogicalProfile(
    allocator: std.mem.Allocator,
    comptime Air: type,
) !static_profile.Profile {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    return static_profile.collect(allocator, &definition.arena, .{
        // The static profiler uses null, rather than zero, for components with
        // verifier-owned preprocessing and no committed main trace.
        .physical_main_columns = if (Air.PHYSICAL_MAIN_COLUMN_COUNT == 0)
            null
        else
            Air.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = Air.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
}
