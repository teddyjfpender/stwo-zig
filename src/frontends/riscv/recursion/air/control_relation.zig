//! Authenticated interaction plan for exact universal control row 0.

const control = @import("control.zig");
const compiler = @import("relation_interaction.zig");
const types = @import("../../air/lang/types.zig");

pub const Runtime = compiler.Runtime(
    control.LOGICAL_INPUT_COUNT,
    control.RELATION_EVENT_COUNT,
    control.LOOKUP_BATCH_SIZE,
);
pub const Plan = Runtime.Plan;
pub const Row = Runtime.Row;
pub const Entry = compiler.Entry;
pub const Claims = Runtime.Claims;
pub const Interaction = Runtime.Interaction;

pub fn authenticate(definition: *const control.Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(
        &definition.arena,
        control.SEMANTIC_DIGEST,
        definition.events,
    );
}

pub fn events(definition: *const control.Definition) [control.RELATION_EVENT_COUNT]types.EffectId {
    return definition.events;
}

comptime {
    if (Runtime.BATCH_COUNT != control.INTERACTION_BATCH_COUNT or
        Runtime.INTERACTION_COLUMN_COUNT != control.INTERACTION_COLUMN_COUNT)
    {
        @compileError("control interaction geometry drifted");
    }
}
