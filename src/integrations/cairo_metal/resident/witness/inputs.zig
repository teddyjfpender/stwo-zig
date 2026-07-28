//! Direct adapted-input materialization for resident Cairo witnesses.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const cairo_adapter = @import("stwo_cairo_frontend").adapter;
const cairo_opcodes = @import("stwo_cairo_frontend").adapter.opcodes;
const direct_inputs = @import("stwo_cairo_frontend").witness.direct_inputs;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

const collectComponent = schedule_bindings.collectComponent;

/// Materializes the direct adapted-input lanes without an intermediate packed
/// matrix. Padding repeats row zero exactly as stwo-cairo's `casm_slot_columns`.
pub fn populateCasmWitnessInputs(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    input: *const cairo_adapter.ProverInput,
) !usize {
    var populated: usize = 0;
    for (cairo_opcodes.direct_witness_lanes) |lane| {
        if (witness_bundle.find(lane.label) == null) continue;
        if (!try populateDirectWitnessInput(allocator, resident_arena, schedule, plan, witness_bundle, input, lane.label))
            return Error.MissingBinding;
        populated += 1;
    }
    return populated;
}

pub fn populateBuiltinSeedWitnessInputs(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    input: *const cairo_adapter.ProverInput,
) !usize {
    var populated: usize = 0;
    for (direct_inputs.builtin_components) |lane| {
        if (witness_bundle.find(lane) == null) continue;
        if (!try populateDirectWitnessInput(allocator, resident_arena, schedule, plan, witness_bundle, input, lane))
            return Error.MissingBinding;
        populated += 1;
    }
    return populated;
}

/// Recreates one directly seeded recorded component in its aliased interaction
/// input slab. Returns false for gather/compact consumers, whose inputs must be
/// reconstructed from producer sub-words instead.
pub fn populateDirectWitnessInput(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    input: *const cairo_adapter.ProverInput,
    component: []const u8,
) !bool {
    const entry = witness_bundle.find(component) orelse return Error.MissingBinding;
    const direct = (try direct_inputs.resolve(input, component)) orelse return false;
    const bindings = try collectComponent(allocator, schedule, plan, "WitnessInput", component);
    defer allocator.free(bindings);
    if (entry.program.n_inputs != direct.columnCount() or bindings.len != direct.columnCount())
        return Error.InvalidCardinality;
    const row_count = bindings[0].size_bytes / 4;
    try direct.validateRowCount(row_count);
    for (bindings, 0..) |binding, column| {
        const bytes = try resident_arena.bytes(binding);
        if (bytes.len != row_count * 4) return Error.InvalidBindingSize;
        const aligned: []align(4) u8 = @alignCast(bytes);
        const destination = std.mem.bytesAsSlice(u32, aligned);
        try direct.writeColumn(column, destination);
    }
    return true;
}
