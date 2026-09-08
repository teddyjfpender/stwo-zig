//! Closed native vtable facts used by cold ProfileV2 revalidation.

const clock_component = @import("../air/clock_update_component.zig");
const hash_component = @import("../air/memory_commitment/hash_component.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const program_interaction = @import("../air/program/interaction.zig");
const statement = @import("../air/statement.zig");
const table_component = @import("../air/lookups/tables/component.zig");
const circuit = @import("../prover/ethereum_circuit_profile_v1.zig");
const narrow_poseidon = @import("../air/memory_commitment/poseidon2_narrow_component_v1.zig");

pub fn constraintCount(kind: statement.InfraKind) usize {
    return constraintCountWithCircuitProfile(kind, .legacy_v4);
}

pub fn constraintCountWithCircuitProfile(kind: statement.InfraKind, profile: circuit.CircuitProfileV1) usize {
    return switch (kind) {
        .program => switch (profile.programPolicy()) {
            .sparse_merkle_v1 => program_interaction.N_CONSTRAINTS,
            .fixed_decoded_table_v1 => program_interaction.N_FIXED_CONSTRAINTS,
        },
        .memory => memory_interaction.N_CONSTRAINTS,
        .clock_update => clock_component.N_CONSTRAINTS,
        .poseidon2 => switch (profile.poseidonLayout()) {
            .legacy_v1 => hash_component.constraintCount(.poseidon2, .narrow_memory),
            .narrow_degree3_v1 => narrow_poseidon.N_CONSTRAINTS,
        },
        .merkle => hash_component.constraintCount(.merkle, .narrow_memory),
        .bitwise,
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => table_component.N_CONSTRAINTS,
    };
}
