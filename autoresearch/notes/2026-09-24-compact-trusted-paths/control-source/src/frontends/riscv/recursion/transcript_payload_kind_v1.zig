//! Canonical transcript payload classification for recursive row preparation.
const program_mod = @import("pcs_transcript_program_v1.zig");
const air = struct {
    const transcript_payload = @import("air/transcript_payload.zig");
};

pub fn payloadKind(kind: program_mod.Source) ?air.transcript_payload.VerifierInputKind {
    if (kind == .canonical_preprocessed_root or kind == .common_preprocessed_root) return .commitment;
    if (kind.isConstantPayload()) return .protocol;
    return switch (kind) {
        .commitment => .commitment,
        .claim_value, .provider_partial, .canonical_wire_boundary => .claimed_sum,
        .sampled_values => .sampled_value,
        .fri_commitment => .fri_commitment,
        .last_layer => .last_layer_coefficient,
        else => null,
    };
}
