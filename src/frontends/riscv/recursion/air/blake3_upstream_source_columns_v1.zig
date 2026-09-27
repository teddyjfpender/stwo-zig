//! Allocation-owned upstream source columns. Indexed emission preserves the
//! legacy logical schedule even when authenticated receipts arrive out of order.
//! Construction masks are released before publication; this owner is not proof
//! authority and canonical parent admission still audits every source tuple.
const std = @import("std");
const Storage = @import("blake3_parent_row_storage.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const View = @import("blake3_recursive_column_rows_v1.zig");
const framework = @import("framework_interaction.zig");

pub fn ForSlots(comptime slots: anytype) type {
    const Owners = blk: {
        var types: [slots.len]type = undefined;
        for (slots, &types) |slot, *T| T.* = Direct.ForAir(Storage.Airs[slot]);
        break :blk std.meta.Tuple(&types);
    };
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        owners: Owners,
        seen: [slots.len][]bool,
        finished: bool = false,

        fn position(comptime slot: usize) usize {
            inline for (slots, 0..) |candidate, i| if (candidate == slot) return i;
            @compileError("upstream owner does not contain this cohort");
        }
        pub fn init(a: std.mem.Allocator, counts: [slots.len]usize) !Self {
            var owners: Owners = undefined;
            var masks: [slots.len][]bool = @splat(&.{});
            var initialized: usize = 0;
            errdefer inline for (slots, 0..) |_, i| {
                if (i < initialized) owners[i].deinit();
                a.free(masks[i]);
            };
            inline for (slots, 0..) |slot, i| {
                owners[i] = try Direct.ForAir(Storage.Airs[slot]).init(a, counts[i]);
                initialized += 1;
                masks[i] = try a.alloc(bool, counts[i]);
                @memset(masks[i], false);
            }
            return .{ .a = a, .owners = owners, .seen = masks };
        }
        pub fn deinit(self: *Self) void {
            inline for (slots, 0..) |_, i| {
                self.owners[i].deinit();
                self.a.free(self.seen[i]);
            }
            self.* = undefined;
        }
        pub fn put(self: *Self, comptime slot: usize, index: usize, row: Storage.Airs[slot].Row) !void {
            const i = comptime position(slot);
            if (self.finished or index >= self.seen[i].len or self.seen[i][index]) return error.InvalidUpstreamSourceColumns;
            const owner = &self.owners[i];
            const physical = framework.committedRow(index, owner.log);
            for (owner.mutable_main, row[0..Storage.Airs[slot].PHYSICAL_MAIN_COLUMN_COUNT]) |values, word| values[physical] = word;
            owner.fixed[index] = Storage.compactFixed(Storage.Airs[slot], row);
            self.seen[i][index] = true;
            owner.next += 1;
        }
        pub fn append(self: *Self, comptime slot: usize, row: Storage.Airs[slot].Row) !void {
            try self.put(slot, self.owners[comptime position(slot)].next, row);
        }
        /// Independent schedule construction remains an admission check even
        /// when the dense fixed row is never retained.
        pub fn putFixed(self: *Self, comptime slot: usize, index: usize, row: Storage.Airs[slot].Row, fixed: Storage.Airs[slot].Row) !void {
            for (Storage.compactFixed(Storage.Airs[slot], row), Storage.compactFixed(Storage.Airs[slot], fixed)) |actual, expected| {
                if (!actual.eql(expected)) return error.InvalidNativeParentRows;
            }
            try self.put(slot, index, row);
        }
        pub fn appendFixed(self: *Self, comptime slot: usize, row: Storage.Airs[slot].Row, fixed: Storage.Airs[slot].Row) !void {
            try self.putFixed(slot, self.owners[comptime position(slot)].next, row, fixed);
        }
        pub fn finish(self: *Self) !void {
            if (self.finished) return error.InvalidUpstreamSourceColumns;
            inline for (slots, 0..) |_, i| {
                try self.owners[i].requireFinished();
                for (self.seen[i]) |present| if (!present) return error.InvalidUpstreamSourceColumns;
            }
            inline for (slots, 0..) |_, i| {
                self.a.free(self.seen[i]);
                self.seen[i] = &.{};
            }
            self.finished = true;
        }
        pub fn view(self: *const Self, comptime slot: usize) !View.ForAir(Storage.Airs[slot]) {
            if (!self.finished) return error.InvalidUpstreamSourceColumns;
            const owner = &self.owners[comptime position(slot)];
            try owner.requireFinished();
            return View.ForAir(Storage.Airs[slot]).init(owner.main, owner.fixed);
        }
        pub fn rowAt(self: *const Self, comptime slot: usize, index: usize) !Storage.Airs[slot].Row {
            const borrowed = try self.view(slot);
            if (index >= borrowed.rowCount()) return error.InvalidUpstreamSourceColumns;
            return borrowed.rowAt(index);
        }
        pub fn count(self: *const Self, comptime slot: usize) usize {
            return self.owners[comptime position(slot)].fixed.len;
        }
        pub fn appendTo(self: *const Self, comptime slot: usize, b: anytype) !void {
            try b.appendBorrowed(slot, try self.view(slot));
        }
    };
}
