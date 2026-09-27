//! Original bounded compact-operand to public fixed-inventory reconstruction.
//! Hashes/recipes are proposals; PAGE fresh verification authenticates fixed
//! roots, private cells and original compression equations independently.
const std = @import("std");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const FoldStage = @import("block_v5_memory_source_fold_premix_v1.zig");
const FoldStore = @import("block_v5_memory_source_fold_operand_store_v1.zig");
const Blake = @import("block_v5_memory_source_packed_blake_columns_v1.zig");
const Hash = @import("block_v5_memory_source_packed_hash_v1.zig");
const Recipe = @import("block_v5_memory_source_blake_semantics_v1.zig").Recipe;
pub const Owner = struct {
    a: std.mem.Allocator,
    rows: []Semantic.FoldRow,
    recipes: []Recipe,
    pub fn deinit(self: *Owner) void {
        self.a.free(self.recipes);
        self.a.free(self.rows);
        self.* = undefined;
    }
    pub fn requireRelease(self: *const Owner, a: std.mem.Allocator, rows: []const Semantic.FoldRow) void {
        if (self.a.ptr != a.ptr or self.a.vtable != a.vtable or self.rows.ptr != rows.ptr or self.rows.len != rows.len) @panic("source PAGE descriptor owner mismatch");
    }
};
pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, expected: Protocol.FoldPin, stored: FoldStore.Pin, limits: FoldStage.Limits) !Owner {
    if (expected.page.count == 0 or expected.page.count > 4096) return error.UntrustedSourcePageLoaderInventory;
    var loaded = try FoldStore.load(a, dir, path, expected.page, expected.plan_id, stored.page_identity, stored, limits.stored);
    defer loaded.deinit();
    const geometry = try Blake.Geometry.fromOperations(loaded.operations, expected.geometry.first_circuit, limits.protocol.fold_cores);
    if (!std.meta.eql(geometry, expected.geometry)) return error.UntrustedSourcePageLoaderInventory;
    var inventory = Owner{ .a = a, .rows = try a.alloc(Semantic.FoldRow, expected.page.count), .recipes = &.{} };
    errdefer inventory.deinit();
    inventory.recipes = try a.alloc(Recipe, geometry.frames);
    var frame: usize = 0;
    var compression: u32 = 0;
    for (inventory.rows, loaded.operations) |*row, operation| {
        const recipes = try Hash.recipes(operation);
        const first_frame = frame;
        const first_compression = compression;
        for (recipes.values[0..recipes.count], 0..) |recipe, slot| {
            const count: u32 = if (recipe.default_height != null) 0 else @intCast((recipe.frame.size() + 63) / 64);
            inventory.recipes[frame] = .{ .slot = @intCast(slot), .multiplicity = recipe.multiplicity, .default_height = recipe.default_height, .compression_count = count, .first_compression = compression };
            frame += 1;
            compression = try std.math.add(u32, compression, count);
        }
        row.* = .{ .descriptor = .{ .kind = operation.kind, .height = operation.coordinate.height }, .recipes = inventory.recipes[first_frame..frame], .first_compression = first_compression, .compressions = compression - first_compression };
    }
    if (frame != geometry.frames or compression != geometry.compressions or !std.meta.eql(try FoldStage.inventoryId(expected.page, geometry.first_circuit, inventory.rows), expected.inventory_id)) return error.UntrustedSourcePageLoaderInventory;
    return inventory;
}
