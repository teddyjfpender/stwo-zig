//! Concrete full64 CPU bus emitter. Acceptance requires physical closure of
//! every emitted relation, immutable ROM and independently expected endpoints.
pub const layout = @import("layout.zig");
pub const types = @import("types.zig");
pub const features = @import("features.zig");
pub const Entry = features.Entry;
pub const row = @import("row.zig");
pub const tuples = @import("tuples.zig");
pub const equations = @import("equations.zig");
pub const component = @import("component.zig");
pub const RowFor = row.RowFor;
pub const rom_component = @import("rom_component.zig");
pub const jalr_equations = @import("jalr_equations.zig");
pub const jalr_component = @import("jalr_component.zig");
