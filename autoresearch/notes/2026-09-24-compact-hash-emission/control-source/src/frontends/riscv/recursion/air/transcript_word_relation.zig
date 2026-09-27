//! Authenticated paired LogUp plan for universal transcript-word row 4.

const component = @import("transcript_word.zig");
const compiler = @import("relation_interaction.zig");
const types = @import("../../air/lang/types.zig");

pub const Runtime = compiler.Runtime(
    component.LOGICAL_INPUT_COUNT,
    component.RELATION_EVENT_COUNT,
    component.LOOKUP_BATCH_SIZE,
);
pub const Plan = Runtime.Plan;
pub const Row = Runtime.Row;
pub const Entry = compiler.Entry;
pub const Claims = Runtime.Claims;
pub const Interaction = Runtime.Interaction;

pub fn authenticate(definition: *const component.Definition) !Plan {
    try definition.validate();
    return Runtime.authenticate(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
    );
}

pub fn events(
    definition: *const component.Definition,
) [component.RELATION_EVENT_COUNT]types.EffectId {
    return definition.events.ordered();
}

comptime {
    if (Runtime.BATCH_COUNT != component.INTERACTION_BATCH_COUNT or
        Runtime.INTERACTION_COLUMN_COUNT != component.INTERACTION_COLUMN_COUNT)
    {
        @compileError("transcript-word interaction geometry drifted");
    }
}
