//! Universal relation binding for the dormant V3 public-I/O word bridge.

const air = @import("v3_public_io_word_bridge_v1.zig");
const factory = @import("universal_relation_binding.zig");

pub const Binding = factory.Binding(air);
pub const Runtime = Binding.Runtime;
pub const Plan = Binding.Plan;

pub fn authenticate(definition: *const air.Definition) !Plan {
    return Binding.authenticate(definition);
}

pub fn events(definition: *const air.Definition) [air.RELATION_EVENT_COUNT]@import("../../air/lang/types.zig").EffectId {
    return Binding.events(definition);
}
