//! Experimental compact-range component order and caller-pinned placement.
const geometry = @import("compact_range_geometry.zig");
const provider = @import("compact_range_provider.zig");
pub const Roster = @import("universal_component_roster.zig").ForAirs(
    .{ provider.Provider(.range_check_20), provider.Provider(.range_check_8_11), provider.Provider(.range_check_8_8_4) },
    &.{ "range20", "range8_11", "range8_8_4" },
);
pub fn admittedManifest(plan: geometry.Plan, expected: [32]u8, origin: Roster.Origin) !Roster.Manifest {
    try plan.admit(expected);
    var result = Roster.Manifest{ .log_sizes = undefined, .origin = origin };
    for (&result.log_sizes, plan.shapes) |*log, shape| log.* = shape.log_size;
    // Validate every placement, including origin arithmetic, before exposure.
    inline for (0..Roster.Airs.len) |i| _ = try result.placement(@enumFromInt(i));
    return result;
}
