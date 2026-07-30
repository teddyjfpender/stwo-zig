//! Official Cairo proving through the Metal PCS backend.

pub const transaction = @import("transaction.zig");
/// Re-exported so the Cairo Metal product can inject the device composition
/// stage through the same `integrations.cairo_metal` facade it already uses for
/// the interaction executor.
pub const composition_stage = @import("../composition_stage.zig");
pub const interaction_executor = @import("interaction_executor.zig");
pub const resident_interaction = @import("resident_interaction.zig");
pub const resident_lookup = @import("resident_lookup.zig");

test {
    _ = transaction;
    _ = composition_stage;
    _ = interaction_executor;
    _ = resident_interaction;
    _ = resident_lookup;
}
