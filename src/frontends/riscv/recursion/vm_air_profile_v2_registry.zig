//! Closed native vtable facts used by cold ProfileV2 revalidation.

const clock_component = @import("../air/clock_update_component.zig");
const hash_component = @import("../air/memory_commitment/hash_component.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const program_interaction = @import("../air/program/interaction.zig");
const statement = @import("../air/statement.zig");
const table_component = @import("../air/lookups/tables/component.zig");

pub fn constraintCount(kind: statement.InfraKind) usize {
    return switch (kind) {
        .program => program_interaction.N_CONSTRAINTS,
        .memory => memory_interaction.N_CONSTRAINTS,
        .clock_update => clock_component.N_CONSTRAINTS,
        .poseidon2 => hash_component.constraintCount(.poseidon2, .narrow_memory),
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
