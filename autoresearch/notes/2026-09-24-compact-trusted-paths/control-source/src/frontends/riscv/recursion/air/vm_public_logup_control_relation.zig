//! Authenticated interaction binding for authority-spine row 17.

const Air = @import("vm_public_logup_control.zig").Air;
const factory = @import("control_slice_relation.zig");

pub const Relation = factory.Binding(Air);
