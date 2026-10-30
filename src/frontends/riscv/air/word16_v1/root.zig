//! Experimental local-algebra namespace. No released path imports it; no
//! complete provider, original or recursive proof has been qualified.
pub const abi = @import("abi.zig");
pub const relations = @import("relations.zig");
pub const legacy_adapter = @import("legacy_adapter.zig");
pub const arithmetic = @import("arithmetic.zig");
pub const logic = @import("logic.zig");
pub const load_store = @import("load_store.zig");
pub const writer = @import("writer.zig");
pub const range_plan = @import("range_plan.zig");
pub const manifest = @import("manifest.zig");
pub const projection = @import("projection.zig");
