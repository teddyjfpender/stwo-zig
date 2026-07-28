//! Fixed-table lookup recipe ownership and active schedule indexing.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../../../backends/metal/protocol_recipes.zig");
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

const oneComponent = schedule_bindings.oneComponent;
const oneOrdinal = schedule_bindings.oneOrdinal;

pub fn prepareFixedTableBatch(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
) !protocol_recipes.FixedTableBatchRecipe {
    var bindings = std.ArrayList(protocol_recipes.FixedTableBindings).empty;
    defer bindings.deinit(allocator);
    var owned_sources = std.ArrayList([]arena_plan.Binding).empty;
    defer {
        for (owned_sources.items) |items| allocator.free(items);
        owned_sources.deinit(allocator);
    }
    var owned_multiplicities = std.ArrayList([]arena_plan.Binding).empty;
    defer {
        for (owned_multiplicities.items) |items| allocator.free(items);
        owned_multiplicities.deinit(allocator);
    }
    for (fixed_bundle.entries) |entry| {
        const destination = oneComponent(schedule, plan, "LookupInputs", entry.component) catch |err| switch (err) {
            schedule_bindings.Error.MissingBinding => continue,
            else => return err,
        };
        const sources = try allocator.alloc(arena_plan.Binding, entry.preprocessed_sources.len);
        var sources_owned = false;
        errdefer if (!sources_owned) allocator.free(sources);
        for (entry.preprocessed_sources, sources) |identity, *source| {
            const ordinal_value = fixed_bundle.identityOrdinal(identity) orelse return Error.MissingBinding;
            source.* = try oneOrdinal(schedule, plan, "PreprocessedEvaluations", ordinal_value);
        }
        try owned_sources.append(allocator, sources);
        sources_owned = true;
        const multiplicity_slab = try oneComponent(schedule, plan, "FixedMultiplicity", entry.component);
        const multiplicities = try allocator.alloc(arena_plan.Binding, entry.multiplicity_columns);
        var multiplicities_owned = false;
        errdefer if (!multiplicities_owned) allocator.free(multiplicities);
        const column_bytes = @as(u64, entry.row_count) * 4;
        if (multiplicity_slab.size_bytes != column_bytes * entry.multiplicity_columns) return Error.InvalidBindingSize;
        for (multiplicities, 0..) |*column, index| {
            column.* = multiplicity_slab;
            column.offset_bytes += @as(u64, @intCast(index)) * column_bytes;
            column.size_bytes = column_bytes;
        }
        try owned_multiplicities.append(allocator, multiplicities);
        multiplicities_owned = true;
        try bindings.append(allocator, .{
            .row_count = entry.row_count,
            .descriptors = entry.lookup_descriptors,
            .sources = sources,
            .multiplicities = multiplicities,
            .destination = destination,
        });
    }
    for (fixed_bundle.entries, 0..) |entry, entry_index| {
        const destination = oneComponent(schedule, plan, "LookupInputs", entry.component) catch continue;
        if (destination.offset_bytes >= @as(u64, std.math.maxInt(u32)) * 4) {
            std.debug.print("fixed_table_high_binding index={d} component={s} destination_offset={d} destination_size={d} rows={d}\n", .{
                entry_index, entry.component, destination.offset_bytes, destination.size_bytes, entry.row_count,
            });
        }
    }
    return protocol_recipes.FixedTableBatchRecipe.init(allocator, metal, resident_arena, bindings.items);
}

/// Resolves a component into the filtered plan order used by
/// `prepareFixedTableBatch`. This order is intentionally independent of the
/// fixed BaseTrace-copy subset owned by `NativeBaseInterpolationBatch`.
pub fn fixedLookupIndex(
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    component: []const u8,
) !?usize {
    var active_index: usize = 0;
    var found: ?usize = null;
    for (fixed_bundle.entries) |entry| {
        _ = oneComponent(schedule, plan, "LookupInputs", entry.component) catch |err| switch (err) {
            schedule_bindings.Error.MissingBinding => continue,
            else => return err,
        };
        if (std.mem.eql(u8, entry.component, component)) {
            if (found != null) return Error.DuplicateBinding;
            found = active_index;
        }
        active_index += 1;
    }
    return found;
}
