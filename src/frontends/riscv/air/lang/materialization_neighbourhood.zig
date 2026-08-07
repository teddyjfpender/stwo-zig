//! Canonical semantic-edge edits for materialization search.
//!
//! Edit kinds are interleaved by ordinal so a finite evaluation budget samples
//! removals, additions, and swaps rather than exhausting one class first.

const std = @import("std");
const cut_set = @import("materialization_cut_set.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const types = @import("types.zig");

pub const Error = cut_set.Error || error{CountOverflow};

pub const Neighbourhood = struct {
    allocator: std.mem.Allocator,
    edits: []cut_set.Edit,
    truncated: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        cut: *const cut_set.CutSet,
        max_edits: usize,
    ) Error!Neighbourhood {
        try cut.validateAgainst(allocator, arena, .{
            .roots = cut.roots,
            .gate = cut.gate,
            .policy = cut.policy,
        });
        const node_count = arena.nodeCount();
        const flag_count = std.math.mul(usize, node_count, 4) catch
            return error.CountOverflow;
        const flags = try allocator.alloc(bool, flag_count);
        defer allocator.free(flags);
        @memset(flags, false);
        const selected = flags[0..node_count];
        const roots = flags[node_count .. node_count * 2];
        const reachable = flags[node_count * 2 .. node_count * 3];
        const addition_flags = flags[node_count * 3 .. node_count * 4];
        for (cut.values) |value| selected[types.idIndex(value)] = true;
        for (cut.roots) |root| roots[types.idIndex(root)] = true;
        markReachable(arena, cut.roots, reachable);

        var removals: std.ArrayList(types.ValueId) = .empty;
        defer removals.deinit(allocator);
        for (cut.values) |value| if (!roots[types.idIndex(value)])
            try removals.append(allocator, value);
        for (arena.nodesView(), 0..) |node, parent_index| {
            if (!reachable[parent_index]) continue;
            for (operands(node.key.op)) |optional| {
                const operand = optional orelse continue;
                const operand_index = types.idIndex(operand);
                if (selected[parent_index] and !selected[operand_index] and
                    isDerivedScalar(arena.nodesView()[operand_index]))
                {
                    addition_flags[operand_index] = true;
                }
                if (selected[operand_index] and !selected[parent_index] and
                    isDerivedScalar(node))
                {
                    addition_flags[parent_index] = true;
                }
            }
        }
        var additions: std.ArrayList(types.ValueId) = .empty;
        defer additions.deinit(allocator);
        for (addition_flags, 0..) |is_addition, index| if (is_addition)
            try additions.append(allocator, @enumFromInt(index));

        var swaps: std.ArrayList(Swap) = .empty;
        defer swaps.deinit(allocator);
        for (arena.nodesView(), 0..) |node, parent_index| {
            if (!reachable[parent_index]) continue;
            const parent: types.ValueId = @enumFromInt(parent_index);
            for (operands(node.key.op)) |optional| {
                const operand = optional orelse continue;
                const operand_index = types.idIndex(operand);
                if (selected[parent_index] and !roots[parent_index] and
                    addition_flags[operand_index])
                {
                    try swaps.append(allocator, .{ .remove = parent, .add = operand });
                }
                if (selected[operand_index] and !roots[operand_index] and
                    addition_flags[parent_index])
                {
                    try swaps.append(allocator, .{ .remove = operand, .add = parent });
                }
            }
        }
        std.mem.sort(Swap, swaps.items, {}, swapLessThan);
        var unique_swaps: usize = 0;
        for (swaps.items) |item| {
            if (unique_swaps != 0 and std.meta.eql(swaps.items[unique_swaps - 1], item))
                continue;
            swaps.items[unique_swaps] = item;
            unique_swaps += 1;
        }
        swaps.shrinkRetainingCapacity(unique_swaps);

        var edits: std.ArrayList(cut_set.Edit) = .empty;
        defer edits.deinit(allocator);
        const edit_count = std.math.add(
            usize,
            removals.items.len,
            additions.items.len,
        ) catch return error.CountOverflow;
        const total_edits = std.math.add(usize, edit_count, swaps.items.len) catch
            return error.CountOverflow;
        const count = @max(removals.items.len, @max(additions.items.len, swaps.items.len));
        for (0..count) |index| {
            if (edits.items.len == max_edits) break;
            if (index < removals.items.len) {
                try edits.append(allocator, .{ .remove = removals.items[index] });
                if (edits.items.len == max_edits) break;
            }
            if (index < additions.items.len) {
                try edits.append(allocator, .{ .add = additions.items[index] });
                if (edits.items.len == max_edits) break;
            }
            if (index < swaps.items.len) {
                try edits.append(allocator, .{ .swap = .{
                    .remove = swaps.items[index].remove,
                    .add = swaps.items[index].add,
                } });
            }
        }
        return .{
            .allocator = allocator,
            .edits = try edits.toOwnedSlice(allocator),
            .truncated = total_edits > max_edits,
        };
    }

    pub fn deinit(self: *Neighbourhood) void {
        self.allocator.free(self.edits);
        self.* = undefined;
    }
};

const Swap = struct { remove: types.ValueId, add: types.ValueId };

fn swapLessThan(_: void, lhs: Swap, rhs: Swap) bool {
    const lhs_remove = types.idIndex(lhs.remove);
    const rhs_remove = types.idIndex(rhs.remove);
    if (lhs_remove != rhs_remove) return lhs_remove < rhs_remove;
    return types.idIndex(lhs.add) < types.idIndex(rhs.add);
}

fn operands(op: expr.Op) [3]?types.ValueId {
    return switch (op) {
        .constant, .input, .hint_output, .call_output => .{ null, null, null },
        .add, .sub, .mul => |binary| .{ binary.lhs, binary.rhs, null },
        .neg => |value| .{ value, null, null },
        .select => |selection| .{
            selection.selector,
            selection.when_true,
            selection.when_false,
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| .{ address.index, null, null },
            .access_clock => |clock| .{ clock.instruction_clock, null, null },
            .strict_clock_gap => |gap| .{
                gap.current_clock,
                gap.previous_clock,
                null,
            },
        },
    };
}

fn isDerivedScalar(node: expr.Node) bool {
    if (!node.key.ty.isFieldScalar()) return false;
    return switch (node.key.op) {
        .add, .sub, .mul, .neg, .select, .machine_derived => true,
        else => false,
    };
}

fn markReachable(arena: *const ir.Arena, roots: []const types.ValueId, flags: []bool) void {
    @memset(flags, false);
    for (roots) |root| flags[types.idIndex(root)] = true;
    var reverse = flags.len;
    while (reverse > 0) {
        reverse -= 1;
        if (!flags[reverse]) continue;
        for (operands(arena.nodesView()[reverse].key.op)) |operand| {
            if (operand) |value| flags[types.idIndex(value)] = true;
        }
    }
}
