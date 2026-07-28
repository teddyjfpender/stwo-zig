//! Canonical AIR and commitment ordering for resident Cairo trace trees.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const composition_bundle_mod = @import("stwo_cairo_frontend").witness.composition_bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

const NamedBinding = schedule_bindings.NamedBinding;
const logicalId = schedule_bindings.logicalId;
const ordinal = schedule_bindings.ordinal;
const purpose = schedule_bindings.purpose;

pub fn collectCommitmentOrder(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    name: []const u8,
) ![]arena_plan.Binding {
    const Item = struct { schedule_index: usize, binding: arena_plan.Binding };
    var items = std.ArrayList(Item).empty;
    defer items.deinit(allocator);
    for (schedule, 0..) |entry, schedule_index| {
        if (std.mem.eql(u8, try purpose(entry), name)) try items.append(allocator, .{
            .schedule_index = schedule_index,
            .binding = plan.binding(try logicalId(entry)) catch return Error.MissingBinding,
        });
    }
    if (items.items.len == 0) return Error.MissingBinding;
    std.mem.sortUnstable(Item, items.items, {}, struct {
        fn lessThan(_: void, lhs: Item, rhs: Item) bool {
            if (lhs.binding.size_bytes != rhs.binding.size_bytes) return lhs.binding.size_bytes < rhs.binding.size_bytes;
            return lhs.schedule_index < rhs.schedule_index;
        }
    }.lessThan);
    const result = try allocator.alloc(arena_plan.Binding, items.items.len);
    for (items.items, result) |item, *binding| binding.* = item.binding;
    return result;
}

fn sortCanonicalCommitmentOrder(
    allocator: std.mem.Allocator,
    bindings: []arena_plan.Binding,
) !void {
    const Item = struct { canonical_index: usize, binding: arena_plan.Binding };
    const items = try allocator.alloc(Item, bindings.len);
    defer allocator.free(items);
    for (bindings, items, 0..) |binding, *item, canonical_index|
        item.* = .{ .canonical_index = canonical_index, .binding = binding };
    std.mem.sortUnstable(Item, items, {}, struct {
        fn lessThan(_: void, lhs: Item, rhs: Item) bool {
            if (lhs.binding.size_bytes != rhs.binding.size_bytes)
                return lhs.binding.size_bytes < rhs.binding.size_bytes;
            return lhs.canonical_index < rhs.canonical_index;
        }
    }.lessThan);
    for (items, bindings) |item, *binding| binding.* = item.binding;
}

pub fn commitmentOrderCopy(
    allocator: std.mem.Allocator,
    canonical: []const arena_plan.Binding,
) ![]arena_plan.Binding {
    const commitment = try allocator.dupe(arena_plan.Binding, canonical);
    errdefer allocator.free(commitment);
    try sortCanonicalCommitmentOrder(allocator, commitment);
    return commitment;
}

pub fn reorderTraceQueryValues(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    values_binding: arena_plan.Binding,
    commitment: []const arena_plan.Binding,
    canonical: []const arena_plan.Binding,
    query_stride: usize,
) !void {
    if (commitment.len != canonical.len or query_stride == 0) return Error.InvalidCardinality;
    var already_canonical = true;
    for (commitment, canonical) |committed, air| {
        already_canonical = already_canonical and committed.logical_id == air.logical_id;
    }
    if (already_canonical) return;

    const required_words = std.math.mul(usize, commitment.len, query_stride) catch
        return Error.InvalidBindingSize;
    const bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(values_binding));
    const words = std.mem.bytesAsSlice(u32, bytes);
    if (words.len < required_words) return Error.InvalidBindingSize;
    try reorderColumnMajorValues(
        allocator,
        words[0..required_words],
        commitment,
        canonical,
        query_stride,
    );
}

fn reorderColumnMajorValues(
    allocator: std.mem.Allocator,
    values: []u32,
    commitment: []const arena_plan.Binding,
    canonical: []const arena_plan.Binding,
    stride: usize,
) !void {
    if (commitment.len != canonical.len or stride == 0 or
        values.len != std.math.mul(usize, commitment.len, stride) catch return Error.InvalidBindingSize)
        return Error.InvalidCardinality;

    var canonical_indices = std.AutoHashMap(u32, usize).init(allocator);
    defer canonical_indices.deinit();
    for (canonical, 0..) |binding, canonical_index| {
        const result = try canonical_indices.getOrPut(binding.logical_id);
        if (result.found_existing) return Error.DuplicateBinding;
        result.value_ptr.* = canonical_index;
    }

    const reordered = try allocator.alloc(u32, values.len);
    defer allocator.free(reordered);
    const assigned = try allocator.alloc(bool, commitment.len);
    defer allocator.free(assigned);
    @memset(assigned, false);
    for (commitment, 0..) |binding, commitment_index| {
        const canonical_index = canonical_indices.get(binding.logical_id) orelse
            return Error.MissingBinding;
        if (assigned[canonical_index]) return Error.DuplicateBinding;
        assigned[canonical_index] = true;
        @memcpy(
            reordered[canonical_index * stride ..][0..stride],
            values[commitment_index * stride ..][0..stride],
        );
    }
    for (assigned) |present| if (!present) return Error.MissingBinding;
    @memcpy(values, reordered);
}

pub fn canonicalTraceTree(
    allocator: std.mem.Allocator,
    bundle: composition_bundle_mod.Bundle,
    named: []const NamedBinding,
    tree_index: u32,
) ![]arena_plan.Binding {
    var column_count: usize = 0;
    for (bundle.components) |component| {
        var found = false;
        for (component.trace_spans) |span| {
            if (span.tree != tree_index) continue;
            if (found or span.start > span.end) return Error.InvalidBindingSize;
            found = true;
            column_count = @max(column_count, span.end);
        }
        if (!found) return Error.InvalidBindingSize;
    }
    if (column_count != named.len) return Error.InvalidCardinality;

    const result = try allocator.alloc(arena_plan.Binding, column_count);
    errdefer allocator.free(result);
    const assigned = try allocator.alloc(bool, column_count);
    defer allocator.free(assigned);
    @memset(assigned, false);

    var cursors = std.StringHashMap(usize).init(allocator);
    defer cursors.deinit();
    for (bundle.components) |component| {
        const captured_label = if (std.mem.eql(u8, component.label, "memory_id_to_small"))
            "memory_id_to_big"
        else
            component.label;
        var wanted: ?composition_bundle_mod.TraceSpan = null;
        for (component.trace_spans) |span| {
            if (span.tree != tree_index) continue;
            if (wanted != null) return Error.InvalidBindingSize;
            wanted = span;
        }
        const span = wanted orelse return Error.InvalidBindingSize;
        const count: usize = span.end - span.start;
        const skipped = cursors.get(captured_label) orelse 0;
        var seen: usize = 0;
        var copied: usize = 0;
        for (named) |item| {
            if (!std.mem.eql(u8, item.component, captured_label)) continue;
            if (seen < skipped) {
                seen += 1;
                continue;
            }
            if (copied == count) break;
            if (item.ordinal != copied) return Error.InvalidSchedule;
            const destination: usize = span.start + copied;
            if (destination >= result.len or assigned[destination]) return Error.DuplicateBinding;
            result[destination] = item.binding;
            assigned[destination] = true;
            if (tree_index == 2 and std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_INTERACTION_EVAL_DIGESTS"))
                std.debug.print(
                    "interaction_canonical_map index={} component={s} instance={} captured_component={s} captured_index={} logical_id={}\n",
                    .{ destination, component.label, component.instance, captured_label, skipped + copied, item.binding.logical_id },
                );
            copied += 1;
            seen += 1;
        }
        if (copied != count) {
            std.debug.print(
                "canonical tree {} missing {s}[{}]: span={}..{} skipped={} copied={}\n",
                .{ tree_index, component.label, component.instance, span.start, span.end, skipped, copied },
            );
            return Error.MissingBinding;
        }
        try cursors.put(captured_label, skipped + count);
    }
    for (assigned) |present| if (!present) return Error.MissingBinding;
    for (named) |item| {
        const consumed = cursors.get(item.component) orelse 0;
        var available: usize = 0;
        for (named) |candidate| if (std.mem.eql(u8, candidate.component, item.component)) {
            available += 1;
        };
        if (consumed != available) return Error.InvalidCardinality;
    }
    return result;
}

pub fn collectTreePurpose(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    name: []const u8,
    tree_index: u32,
) ![]arena_plan.Binding {
    const Item = struct { ordinal_value: u32, binding: arena_plan.Binding };
    var items = std.ArrayList(Item).empty;
    defer items.deinit(allocator);
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), name)) continue;
        const ordinal_value = try ordinal(entry);
        if (ordinal_value >> 20 != tree_index) continue;
        try items.append(allocator, .{ .ordinal_value = ordinal_value, .binding = plan.binding(try logicalId(entry)) catch return Error.MissingBinding });
    }
    if (items.items.len == 0) return Error.MissingBinding;
    std.mem.sortUnstable(Item, items.items, {}, struct {
        fn lessThan(_: void, lhs: Item, rhs: Item) bool {
            return lhs.ordinal_value < rhs.ordinal_value;
        }
    }.lessThan);
    const result = try allocator.alloc(arena_plan.Binding, items.items.len);
    for (items.items, result) |item, *binding| binding.* = item.binding;
    return result;
}

test "Cairo AIR trace order remains separate from commitment degree order" {
    const canonical = [_]arena_plan.Binding{
        .{
            .logical_id = 10,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = 64,
            .materialization = .resident,
            .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
        },
        .{
            .logical_id = 11,
            .slot = 1,
            .offset_bytes = 64,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
        },
        .{
            .logical_id = 20,
            .slot = 2,
            .offset_bytes = 80,
            .size_bytes = 4,
            .materialization = .resident,
            .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
        },
        .{
            .logical_id = 21,
            .slot = 3,
            .offset_bytes = 84,
            .size_bytes = 64,
            .materialization = .resident,
            .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
        },
    };
    const commitment = try commitmentOrderCopy(std.testing.allocator, &canonical);
    defer std.testing.allocator.free(commitment);

    for (canonical, [_]u32{ 10, 11, 20, 21 }) |binding, expected|
        try std.testing.expectEqual(expected, binding.logical_id);
    for (commitment, [_]u32{ 20, 11, 10, 21 }) |binding, expected|
        try std.testing.expectEqual(expected, binding.logical_id);

    var queried_values = [_]u32{ 200, 201, 110, 111, 100, 101, 210, 211 };
    try reorderColumnMajorValues(
        std.testing.allocator,
        &queried_values,
        commitment,
        &canonical,
        2,
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 100, 101, 110, 111, 200, 201, 210, 211 },
        &queried_values,
    );

    var missing = canonical;
    missing[3].logical_id = 99;
    try std.testing.expectError(
        Error.MissingBinding,
        reorderColumnMajorValues(
            std.testing.allocator,
            &queried_values,
            commitment,
            &missing,
            2,
        ),
    );
}
