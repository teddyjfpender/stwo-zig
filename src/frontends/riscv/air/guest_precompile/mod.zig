//! Proof-facing primitives admitted only by guest-precompile profiles.

pub const relation_registry = @import("relation_registry.zig");
pub const relation_challenges = @import("relation_challenges.zig");
pub const relation_event = @import("relation_event.zig");
