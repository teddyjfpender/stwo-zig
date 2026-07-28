//! Canonical relation claimed-sum ordering and schedule validation.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const composition_bundle_mod = @import("stwo_cairo_frontend").witness.composition_bundle;
const relation_bundle_mod = @import("stwo_cairo_frontend").witness.relation_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

pub fn canonicalClaimedSumBindings(
    allocator: std.mem.Allocator,
    composition_bundle: composition_bundle_mod.Bundle,
    relation_bundle: relation_bundle_mod.Bundle,
    scheduled: []const arena_plan.Binding,
) ![]arena_plan.Binding {
    if (composition_bundle.components.len != scheduled.len) return Error.InvalidClaimedSumCount;
    const canonical = try allocator.alloc(arena_plan.Binding, scheduled.len);
    errdefer allocator.free(canonical);
    const assigned = try allocator.alloc(bool, scheduled.len);
    defer allocator.free(assigned);
    @memset(assigned, false);

    var scheduled_index: usize = 0;
    for (relation_bundle.components) |relation_component| {
        for (composition_bundle.components, 0..) |component, canonical_index| {
            const relation_label = if (std.mem.eql(u8, component.label, "memory_id_to_small"))
                "memory_id_to_big"
            else
                component.label;
            if (!std.mem.eql(u8, relation_label, relation_component.name)) continue;
            if (scheduled_index >= scheduled.len or assigned[canonical_index])
                return Error.InvalidClaimedSumCount;
            canonical[canonical_index] = scheduled[scheduled_index];
            assigned[canonical_index] = true;
            scheduled_index += 1;
        }
    }
    if (scheduled_index != scheduled.len) return Error.InvalidClaimedSumCount;
    for (assigned) |present| if (!present) return Error.InvalidClaimedSumCount;
    return canonical;
}

pub fn validateClaimedSumOrder(
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    claimed_sums: []const arena_plan.Binding,
) !void {
    if (claimed_sums.len == 0 or claimed_sums.len > 256) return Error.InvalidClaimedSumCount;
    var seen = [_]bool{false} ** 256;
    var count: usize = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try schedule_bindings.purpose(entry), "RelationClaimedSum")) continue;
        const claimed_ordinal = try schedule_bindings.ordinal(entry);
        if (claimed_ordinal >= claimed_sums.len or seen[claimed_ordinal]) return Error.InvalidClaimedSumCount;
        const binding = plan.binding(try schedule_bindings.logicalId(entry)) catch return Error.MissingBinding;
        if (!std.meta.eql(binding, claimed_sums[claimed_ordinal])) return Error.InvalidSchedule;
        seen[claimed_ordinal] = true;
        count += 1;
    }
    if (count != claimed_sums.len) return Error.InvalidClaimedSumCount;
}

test "Cairo relation claimed sums require contiguous exact bindings" {
    var plan_bindings = [_]arena_plan.Binding{
        .{
            .logical_id = 40,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        },
        .{
            .logical_id = 41,
            .slot = 1,
            .offset_bytes = 16,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        },
    };
    var empty_slots: [0]arena_plan.Slot = .{};
    var empty_actions: [0]arena_plan.Action = .{};
    var empty_offsets: [0]usize = .{};
    const plan = arena_plan.Plan{
        .allocator = std.testing.allocator,
        .bindings = &plan_bindings,
        .slots = &empty_slots,
        .actions = &empty_actions,
        .action_offsets = &empty_offsets,
        .total_bytes = 32,
        .peak_live_bytes = 32,
        .plan_hash = 0,
    };
    const claimed_sums = [_]arena_plan.Binding{ plan_bindings[0], plan_bindings[1] };
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[
        \\  {"purpose":"RelationClaimedSum","ordinal":1,"id":41},
        \\  {"purpose":"RelationClaimedSum","ordinal":0,"id":40}
        \\]
    ,
        .{},
    );
    defer parsed.deinit();
    try validateClaimedSumOrder(parsed.value.array.items, plan, &claimed_sums);

    const swapped = [_]arena_plan.Binding{ plan_bindings[1], plan_bindings[0] };
    try std.testing.expectError(
        Error.InvalidSchedule,
        validateClaimedSumOrder(parsed.value.array.items, plan, &swapped),
    );

    var duplicate = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[
        \\  {"purpose":"RelationClaimedSum","ordinal":0,"id":40},
        \\  {"purpose":"RelationClaimedSum","ordinal":0,"id":41}
        \\]
    ,
        .{},
    );
    defer duplicate.deinit();
    try std.testing.expectError(
        Error.InvalidClaimedSumCount,
        validateClaimedSumOrder(duplicate.value.array.items, plan, &claimed_sums),
    );
}

test "Cairo claimed sums follow Rust interaction claim order" {
    var composition = try composition_bundle_mod.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();
    var relations = try relation_bundle_mod.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();

    var scheduled: [58]arena_plan.Binding = undefined;
    for (&scheduled, 0..) |*binding, index| binding.* = .{
        .logical_id = @intCast(index),
        .slot = @intCast(index),
        .offset_bytes = index * 16,
        .size_bytes = 16,
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    const canonical = try canonicalClaimedSumBindings(
        std.testing.allocator,
        composition,
        relations,
        &scheduled,
    );
    defer std.testing.allocator.free(canonical);

    const expected_relation_ordinals = [_]u32{
        1,  2,  0,  3,  5,  4,  7,  11, 12, 15, 16, 17, 18, 19, 23,
        24, 50, 57, 9,  8,  10, 51, 52, 6,  28, 32, 49, 14, 25, 27,
        26, 29, 31, 30, 33, 13, 34, 39, 20, 21, 22, 45, 47, 35, 36,
        37, 38, 42, 43, 48, 46, 41, 44, 40, 53, 54, 55, 56,
    };
    try std.testing.expectEqual(expected_relation_ordinals.len, canonical.len);
    for (canonical, expected_relation_ordinals) |binding, expected|
        try std.testing.expectEqual(expected, binding.logical_id);
}
