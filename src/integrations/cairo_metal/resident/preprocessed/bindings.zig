//! Resolves canonical preprocessed identities to resident schedule bindings.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

pub fn collect(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    identities: []const []u8,
) ![]arena_plan.Binding {
    const sources = try allocator.alloc(arena_plan.Binding, identities.len);
    errdefer allocator.free(sources);
    for (identities, sources) |identity, *source| {
        const wanted = fixed_bundle.identityOrdinal(identity) orelse return Error.MissingBinding;
        source.* = try schedule_bindings.oneOrdinal(schedule, plan, "PreprocessedEvaluations", wanted);
    }
    return sources;
}
