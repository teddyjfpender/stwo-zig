//! Universal-relation binding for the V2 VM public-LogUp control row.

const air = @import("vm_public_logup_control_v2.zig");
const factory = @import("universal_relation_binding.zig");

pub const Binding = factory.Binding(air);
pub const Runtime = Binding.Runtime;
pub const Plan = Binding.Plan;
pub const Row = Binding.Row;
pub const Entry = Binding.Entry;
pub const Claims = Binding.Claims;
pub const Interaction = Binding.Interaction;

pub fn authenticate(definition: *const air.Definition) !Plan {
    return Binding.authenticate(definition);
}

pub fn events(
    definition: *const air.Definition,
) [air.RELATION_EVENT_COUNT]@import("../../air/lang/types.zig").EffectId {
    return Binding.events(definition);
}
