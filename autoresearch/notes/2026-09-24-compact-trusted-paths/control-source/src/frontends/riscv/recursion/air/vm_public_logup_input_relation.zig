//! Authenticated multi-relation interaction for authority-spine row 16.

const air = @import("vm_public_logup_input.zig");
const compiler = @import("relation_interaction.zig");

pub const Runtime = compiler.Runtime(
    air.LOGICAL_INPUT_COUNT,
    air.RELATION_EVENT_COUNT,
    air.LOOKUP_BATCH_SIZE,
);
pub const Plan = Runtime.Plan;
pub const Row = Runtime.Row;
pub const Entry = compiler.Entry;
pub const Claims = Runtime.Claims;
pub const Interaction = Runtime.Interaction;

pub fn authenticate(definition: *const air.Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(
        &definition.arena,
        air.SEMANTIC_DIGEST,
        definition.events,
    );
}

comptime {
    if (Runtime.BATCH_COUNT != air.INTERACTION_BATCH_COUNT or
        Runtime.INTERACTION_COLUMN_COUNT != air.INTERACTION_COLUMN_COUNT)
    {
        @compileError("VM public-LogUp input interaction geometry drifted");
    }
}
