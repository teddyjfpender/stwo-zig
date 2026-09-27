//! Public arithmetic-wire vocabulary shared by constraints and lowering.
//! This module contains no graph evaluator or witness materializer.
const QM31 = @import("stwo_core").fields.qm31.QM31;
const relation = @import("../../air/lang/relation.zig");

pub const Mode = enum(u8) { segment, binary };

pub const PublicWireTerm = struct {
    lane: u32,
    active_in: Mode,
    role: relation.Role,
    circuit_id: u32,
    node_id: u32,
    value: QM31,
    multiplicity: u32,
};

pub const VerifierInputKind = enum(u32) {
    protocol = 1,
    statement = 2,
    pcs_parameters = 3,
    commitment = 4,
    claimed_sum = 5,
    sampled_value = 6,
    fri_commitment = 7,
    last_layer_coefficient = 8,
    interaction_pow_nonce = 9,
    pcs_pow_nonce = 10,
    vm_public_claim_digest = 11,
    vm_air_claimed_sum = 12,
};
