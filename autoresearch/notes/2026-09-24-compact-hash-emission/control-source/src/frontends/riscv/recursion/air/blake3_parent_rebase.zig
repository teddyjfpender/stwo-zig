//! Injective namespace relocation for an owned parent witness. All planning and
//! admission precede writes; application edits only identifier columns in place.
//! It does not change the child statement, arithmetic or transcript values.
const std = @import("std");
const core = @import("stwo_core");
const storage = @import("blake3_parent_row_storage.zig");
const ns = @import("blake3_parent_namespace.zig");
const committed = @import("framework_interaction.zig").committedRow;
const M = core.fields.m31.M31;
const Masks = blk: {
    var types: [storage.Airs.len]type = undefined;
    for (storage.Airs, &types) |Air, *T| T.* = [Air.LOGICAL_INPUT_COUNT]bool;
    break :blk std.meta.Tuple(&types);
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    first: u32,
    old: []u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.old);
        self.* = undefined;
    }
    pub fn end(self: *const Plan) !u32 {
        const limit = try std.math.add(u64, self.first, self.old.len);
        if (self.first >= core.fields.m31.Modulus or limit > core.fields.m31.Modulus) return error.InvalidParentRebase;
        for (self.old, 0..) |id, i| if (id >= core.fields.m31.Modulus or (i > 0 and self.old[i - 1] >= id)) return error.InvalidParentRebase;
        return @intCast(limit);
    }
    pub fn identity(self: *const Plan) ![32]u8 {
        _ = try self.end();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42334e53, 1, self.first });
        channel.mixU64(self.old.len);
        channel.mixU32s(self.old);
        inline for (storage.Airs) |Air| @import("../../prover/blake3_execution_protocol.zig").mixDigest(&channel, Air.SEMANTIC_DIGEST);
        return channel.digestBytes();
    }
    pub fn map(self: *const Plan, id: u32) ?u32 {
        var low: usize = 0;
        var high = self.old.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.old[mid] < id) low = mid + 1 else high = mid;
        }
        return if (low < self.old.len and self.old[low] == id) self.first + @as(u32, @intCast(low)) else null;
    }
};
pub fn prepare(a: std.mem.Allocator, parent: *const storage.Prepared, first: u32) !Plan {
    const masks = try geometry(parent);
    var ids = std.AutoHashMap(u32, void).init(a);
    defer ids.deinit();
    inline for (storage.Airs, 0..) |Air, i| for (masks[i], 0..) |used, col| {
        if (used) for (0..parent.fixed[i].len) |row| try ids.put(read(Air, parent, i, col, row).toU32(), {});
    };
    const old = try a.alloc(u32, ids.count());
    errdefer a.free(old);
    var iterator = ids.keyIterator();
    var at: usize = 0;
    while (iterator.next()) |id| {
        old[at] = id.*;
        at += 1;
    }
    std.mem.sort(u32, old, {}, std.sort.asc(u32));
    const plan = Plan{ .allocator = a, .first = first, .old = old };
    _ = try plan.end();
    return plan;
}
pub fn apply(parent: *storage.Prepared, plan: *const Plan, expected: [32]u8) !void {
    if (!std.mem.eql(u8, &try plan.identity(), &expected)) return error.UntrustedParentRebase;
    const masks = try geometry(parent);
    // Complete preflight. A missing identifier cannot leave half-renamed rows.
    inline for (storage.Airs, 0..) |Air, i| for (masks[i], 0..) |used, col| {
        if (used) for (0..parent.fixed[i].len) |row| {
            if (plan.map(read(Air, parent, i, col, row).toU32()) == null) return error.StaleParentRebase;
        };
    };
    inline for (storage.Airs, 0..) |Air, i| for (masks[i], 0..) |used, col| {
        if (used) for (0..parent.fixed[i].len) |row| {
            const value = M.fromCanonical(plan.map(read(Air, parent, i, col, row).toU32()).?);
            if (col < Air.PHYSICAL_MAIN_COLUMN_COUNT) {
                const column = parent.main[i][col];
                @constCast(column.values)[committed(row, column.log_size)] = value;
            } else parent.fixed[i][row][col - Air.PHYSICAL_MAIN_COLUMN_COUNT] = value;
        };
    };
}
fn geometry(parent: *const storage.Prepared) !Masks {
    var masks: Masks = undefined;
    inline for (storage.Airs, 0..) |Air, i| {
        var definition = if (@hasDecl(Air, "Location")) try Air.build(parent.allocator, .generated) else try Air.build(parent.allocator);
        defer definition.deinit();
        masks[i] = try ns.renamingColumns(Air, &definition);
        if (parent.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentRebase;
        for (parent.main[i]) |column| if (column.log_size > 30 or column.values.len != @as(usize, 1) << @intCast(column.log_size) or parent.fixed[i].len > column.values.len) return error.InvalidParentRebase;
    }
    return masks;
}
fn read(comptime Air: type, parent: *const storage.Prepared, comptime i: usize, col: usize, row: usize) M {
    return if (col < Air.PHYSICAL_MAIN_COLUMN_COUNT) parent.main[i][col].values[committed(row, parent.main[i][col].log_size)] else parent.fixed[i][row][col - Air.PHYSICAL_MAIN_COLUMN_COUNT];
}
