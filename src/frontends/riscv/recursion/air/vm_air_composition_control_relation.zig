//! Authenticated interaction binding for authority-spine row 19.

const Air = @import("vm_air_composition_control.zig").Air;
const factory = @import("control_slice_relation.zig");

pub const Relation = factory.Binding(Air);
