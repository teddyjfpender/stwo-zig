//! Source-only candidate. No production CPU selector accepts these roles.
pub const production_admission_open = false;
pub const descriptor = @import("descriptor.zig");
pub const state = @import("state_word.zig");
pub const header = @import("permutation_header.zig");
pub const word = @import("message_word.zig");
pub const lane = @import("permutation_lane.zig");
