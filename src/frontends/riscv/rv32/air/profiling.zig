//! Public typed-AIR profiling facade.
//!
//! Static collection is allocation-explicit and cold. Joining already captured
//! static/runtime evidence is allocation-free and samples no clocks.

pub const static_registry = @import("lang/static_profile_registry.zig");
pub const runtime = @import("lang/runtime_profile.zig");
