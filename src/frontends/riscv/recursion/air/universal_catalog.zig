//! Single compile-time catalog of recursion-local logical AIR owners.
//!
//! The protocol roster remains the authority for the 36-row order and the
//! inventory remains the runtime evidence record. This catalog is the one
//! type-level bridge used wherever Zig must instantiate every logical row.

const roster = @import("universal_roster.zig");

pub const Entry = struct {
    Air: type,
    row: roster.Component,
    /// The three arithmetic components retain an explicit source-location
    /// build selector; every other row has a location-independent builder.
    requires_location: bool = false,
};

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
const qm31_mul = @import("qm31_mul_full.zig");
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
const verifier_randomness = @import("verifier_randomness.zig");
const vm_air_composition_control = @import("vm_air_composition_control.zig").Air;
const vm_air_composition_input = @import("vm_air_composition_input.zig");
const vm_public_claim_hash = @import("vm_public_claim_hash.zig");
const vm_public_claim_input = @import("vm_public_claim_input.zig");
const vm_public_claim_semantics_input = @import("vm_public_claim_semantics_input.zig");
const vm_public_io_hash = @import("vm_public_io_hash.zig");
const vm_public_logup_control = @import("vm_public_logup_control.zig").Air;
const vm_public_logup_input = @import("vm_public_logup_input.zig");

pub const LOGICAL_ROWS = .{
    Entry{ .Air = control, .row = .control },
    Entry{ .Air = transcript_air, .row = .transcript_air },
    Entry{ .Air = transcript_binding, .row = .transcript_binding },
    Entry{ .Air = transcript_state, .row = .transcript_state },
    Entry{ .Air = transcript_word, .row = .transcript_word },
    Entry{ .Air = transcript_payload, .row = .transcript_payload },
    Entry{ .Air = pow_check, .row = .pow_check },
    Entry{ .Air = pow_frame, .row = .pow_frame },
    Entry{ .Air = relation_challenge, .row = .relation_challenge },
    Entry{ .Air = verifier_randomness, .row = .verifier_randomness },
    Entry{ .Air = statement_input, .row = .statement_input },
    Entry{ .Air = statement_semantics_input, .row = .statement_semantics_input },
    Entry{ .Air = vm_public_claim_input, .row = .vm_public_claim_input },
    Entry{ .Air = vm_public_claim_hash, .row = .vm_public_claim_hash },
    Entry{ .Air = vm_public_io_hash, .row = .vm_public_io_hash },
    Entry{
        .Air = vm_public_claim_semantics_input,
        .row = .vm_public_claim_semantics_input,
    },
    Entry{ .Air = vm_public_logup_input, .row = .vm_public_logup_input },
    Entry{ .Air = vm_public_logup_control, .row = .vm_public_logup_control },
    Entry{ .Air = vm_air_composition_input, .row = .vm_air_composition_input },
    Entry{ .Air = vm_air_composition_control, .row = .vm_air_composition_control },
    Entry{ .Air = query_bits, .row = .query_bits },
    Entry{ .Air = query_mapping, .row = .query_mapping },
    Entry{ .Air = merkle_root, .row = .merkle_root },
    Entry{ .Air = trace_merkle, .row = .trace_merkle },
    Entry{ .Air = pcs_deep_input, .row = .pcs_deep_input },
    Entry{ .Air = fri_merkle_leaf, .row = .fri_merkle_leaf },
    Entry{ .Air = fri_merkle_node, .row = .fri_merkle_node },
    Entry{ .Air = fri_merkle_anchor, .row = .fri_merkle_anchor },
    Entry{ .Air = fri_verifier_control, .row = .fri_verifier_control },
    Entry{ .Air = fri_verifier_input, .row = .fri_verifier_input },
    Entry{ .Air = qm31_mul, .row = .qm31_mul, .requires_location = true },
    Entry{ .Air = qm31_inv, .row = .qm31_inv, .requires_location = true },
    Entry{ .Air = linear_ops, .row = .linear_ops, .requires_location = true },
    Entry{ .Air = merkle_path, .row = .merkle_path },
};

pub const LOGICAL_COUNT: usize = LOGICAL_ROWS.len;

comptime {
    if (LOGICAL_COUNT != roster.typedLogicalCount())
        @compileError("universal logical catalog count drifted from roster");
    var seen = [_]bool{false} ** roster.COMPONENT_COUNT;
    var prior: ?u8 = null;
    for (LOGICAL_ROWS) |entry| {
        const row: u8 = @intFromEnum(entry.row);
        if (seen[row]) @compileError("duplicate universal logical catalog row");
        if (prior) |value| if (row <= value)
            @compileError("universal logical catalog order drifted");
        prior = row;
        seen[row] = true;
        if (roster.DESCRIPTORS[row].status != .typed_logical)
            @compileError("catalog row lacks typed-logical roster admission");
        if (!@hasDecl(entry.Air, "SEMANTIC_DIGEST") or
            !@hasDecl(entry.Air, "DIRECT_CONSTRAINT_COUNT") or
            !@hasDecl(entry.Air, "RELATION_EVENT_COUNT"))
        {
            @compileError("catalog AIR lacks compiler-owned identity or geometry");
        }
    }
    for (roster.DESCRIPTORS, 0..) |descriptor, row| {
        if (seen[row] != (descriptor.status == .typed_logical))
            @compileError("universal logical catalog is not exhaustive");
    }
}
