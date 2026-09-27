//! Read circuit identifiers from authenticated typed relation effects. Arbitrary
//! field values are not identifiers, and some older AIRs commit IDs in main.
const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const relation = @import("../../air/lang/relation.zig");
const committed = @import("framework_interaction.zig").committedRow;
pub fn rejectRange(parent: *const storage.Prepared, start: u32, end: u32) !void {
    inline for (storage.Airs, 0..) |Air, i| {
        var definition = if (@hasDecl(Air, "Location")) try Air.build(parent.allocator, .generated) else try Air.build(parent.allocator);
        defer definition.deinit();
        try definition.validate();
        var columns: [Air.LOGICAL_INPUT_COUNT]bool = @splat(false);
        for (definition.arena.effectsView()) |effect| {
            const binding = effect.binding orelse continue;
            if (binding.schema != relation.get(.recursion_wire).id) continue;
            const values = effect.values.slice(definition.arena.effectValuesView()) orelse return error.InvalidParentNamespaceLayout;
            if (values.len != 6) return error.InvalidParentNamespaceLayout;
            const index = @intFromEnum(values[0]);
            const nodes = definition.arena.nodesView();
            if (index >= nodes.len or nodes[index].key.op != .input) return error.InvalidParentNamespaceLayout;
            var column: usize = 0;
            for (nodes[0..index]) |node| if (node.key.op == .input) {
                column += 1;
            };
            if (column >= columns.len) return error.InvalidParentNamespaceLayout;
            columns[column] = true;
        }
        for (columns, 0..) |used, column| {
            if (!used) continue;
            if (column < Air.PHYSICAL_MAIN_COLUMN_COUNT and parent.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentNamespaceLayout;
            for (parent.fixed[i], 0..) |row, logical| {
                const value = if (column < Air.PHYSICAL_MAIN_COLUMN_COUNT) parent.main[i][column].values[committed(logical, parent.main[i][column].log_size)] else row[column];
                if (value.toU32() >= start and value.toU32() < end) return error.InvalidParentCustodyNamespace;
            }
        }
    }
}
