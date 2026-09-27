//! Typed immediate emission for upstream recursive nonhash AIR sources.
//! Construction only: no verifier receipt or public source authority is made.
//! Canonical bounded transcript and opening builders stream into these owners.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Storage = @import("blake3_parent_row_storage.zig");
const Upstream = @import("blake3_upstream_source_columns_v1.zig");
pub const slots = .{ 2, 6, 7, 8, 9, 13, 14, 15 };
pub const Tag = enum { boundary, challenge, route, query_mask, private_word, select, retry_control, counter };
/// Pointers live only for one synchronous call. Emitters must not retain them.
pub const RowRef = union(Tag) {
    boundary: *const Storage.Airs[2].Row,
    challenge: *const Storage.Airs[6].Row,
    route: *const Storage.Airs[7].Row,
    query_mask: *const Storage.Airs[8].Row,
    private_word: *const Storage.Airs[9].Row,
    select: *const Storage.Airs[13].Row,
    retry_control: *const Storage.Airs[14].Row,
    counter: *const Storage.Airs[15].Row,
};
fn tagFor(comptime slot: usize) Tag {
    inline for (slots, std.meta.tags(Tag)) |candidate, tag| if (candidate == slot) return tag;
    @compileError("not an upstream nonhash AIR cohort");
}
fn position(comptime slot: usize) usize {
    inline for (slots, 0..) |candidate, index| if (candidate == slot) return index;
    @compileError("not an upstream nonhash AIR cohort");
}
fn validateFixed(comptime slot: usize, row: *const Storage.Airs[slot].Row, expected: *const Storage.Airs[slot].Row) !void {
    for (Storage.compactFixed(Storage.Airs[slot], row.*), Storage.compactFixed(Storage.Airs[slot], expected.*)) |actual, fixed| {
        if (!actual.eql(fixed)) return error.InvalidNativeParentRows;
    }
}
pub const Sink = struct {
    context: *anyopaque,
    emit_row: *const fn (*anyopaque, RowRef, RowRef) anyerror!void,
    /// Multiplicity patches are expressed as checked deltas, never escaped
    /// mutable pointers. Their exact caller schedule remains source-owned.
    add_coordinate: *const fn (*anyopaque, Tag, usize, usize, u32) anyerror!void,
    row_count: *const fn (*anyopaque, Tag) usize,
    pub fn rowCount(self: Sink, comptime slot: usize) usize {
        return self.row_count(self.context, tagFor(slot));
    }
    pub fn emit(self: Sink, comptime slot: usize, row: *const Storage.Airs[slot].Row, expected: *const Storage.Airs[slot].Row) !void {
        try self.emit_row(self.context, @unionInit(RowRef, @tagName(tagFor(slot)), row), @unionInit(RowRef, @tagName(tagFor(slot)), expected));
    }
    pub fn addUses(self: Sink, comptime slot: usize, index: usize, comptime coordinate: usize, increment: u32) !void {
        comptime if (coordinate >= Storage.Airs[slot].LOGICAL_INPUT_COUNT) @compileError("nonhash coordinate outside AIR row");
        try self.add_coordinate(self.context, tagFor(slot), index, coordinate, increment);
    }
};
/// First pass stores counts and the most recently emitted counter producer.
/// No boundary/routing/query row roster is allocated.
pub const Counts = struct {
    rows: [slots.len]usize = @splat(0),
    last_counter: ?[2]u32 = null,
    pub fn sink(self: *Counts) Sink {
        return .{ .context = self, .emit_row = emit, .add_coordinate = add, .row_count = count };
    }
    fn count(context: *anyopaque, tag: Tag) usize {
        const self: *Counts = @ptrCast(@alignCast(context));
        return self.rows[@intFromEnum(tag)];
    }
    fn emit(context: *anyopaque, row: RowRef, expected: RowRef) !void {
        const self: *Counts = @ptrCast(@alignCast(context));
        if (std.meta.activeTag(row) != std.meta.activeTag(expected)) return error.InvalidNativeParentRows;
        switch (row) {
            inline else => |value, tag| {
                const slot = comptime slots[@intFromEnum(tag)];
                try validateFixed(slot, value, @field(expected, @tagName(tag)));
                const next = try std.math.add(usize, self.rows[position(slot)], 1);
                if (next > 1 << 24) return error.InvalidTraceShape;
                self.rows[position(slot)] = next;
                if (comptime slot == 15) self.last_counter = .{ value[31].v, value[32].v };
            },
        }
    }
    fn add(context: *anyopaque, tag: Tag, index: usize, coordinate: usize, increment: u32) !void {
        const self: *Counts = @ptrCast(@alignCast(context));
        // Child draws can patch an earlier producer after emitting new counters.
        // Shape counting retains no arbitrary earlier source rows. Only the
        // completed emission pass can validate their exact accumulated value.
        if (tag != .counter or self.last_counter == null or index >= self.rows[position(15)] or coordinate < 31 or coordinate > 32 or increment >= core.fields.m31.Modulus) return error.InvalidNonhashMultiplicityPatch;
        // Earlier producers have already been streamed. This count-only pass
        // cannot authenticate their accumulated value; both real emission
        // owners below enforce its exact canonical sum before publication.
        if (index != self.rows[position(15)] - 1) return;
        const sum = try std.math.add(u32, self.last_counter.?[coordinate - 31], increment);
        if (sum >= core.fields.m31.Modulus) return error.InvalidNonhashMultiplicityPatch;
        self.last_counter.?[coordinate - 31] = sum;
    }
};
pub const Owner = struct {
    columns: Upstream.ForSlots(slots),
    pub fn init(a: std.mem.Allocator, counts: Counts) !Owner {
        return .{ .columns = try Upstream.ForSlots(slots).init(a, counts.rows) };
    }
    pub fn deinit(self: *Owner) void {
        self.columns.deinit();
        self.* = undefined;
    }
    pub fn sink(self: *Owner) Sink {
        return .{ .context = self, .emit_row = emit, .add_coordinate = add, .row_count = count };
    }
    fn count(context: *anyopaque, tag: Tag) usize {
        const self: *Owner = @ptrCast(@alignCast(context));
        switch (tag) {
            inline else => |kind| return self.columns.owners[comptime @intFromEnum(kind)].next,
        }
    }
    fn emit(context: *anyopaque, row: RowRef, expected: RowRef) !void {
        const self: *Owner = @ptrCast(@alignCast(context));
        if (std.meta.activeTag(row) != std.meta.activeTag(expected)) return error.InvalidNativeParentRows;
        switch (row) {
            inline else => |value, tag| {
                const slot = comptime slots[@intFromEnum(tag)];
                try self.columns.appendFixed(slot, value.*, @field(expected, @tagName(tag)).*);
            },
        }
    }
    fn add(context: *anyopaque, tag: Tag, index: usize, coordinate: usize, increment: u32) !void {
        const self: *Owner = @ptrCast(@alignCast(context));
        if (tag != .counter or self.columns.finished or self.columns.owners[comptime position(15)].next == 0 or index >= self.columns.owners[comptime position(15)].next or coordinate < 31 or coordinate > 32) return error.InvalidNonhashMultiplicityPatch;
        const owner = &self.columns.owners[comptime position(15)];
        if (index >= owner.fixed.len or !self.columns.seen[position(15)][index]) return error.InvalidNonhashMultiplicityPatch;
        const value = &owner.fixed[index][coordinate - Storage.Airs[15].PHYSICAL_MAIN_COLUMN_COUNT];
        const sum = try std.math.add(u32, value.v, increment);
        if (sum >= core.fields.m31.Modulus) return error.InvalidNonhashMultiplicityPatch;
        value.* = M.fromCanonical(sum);
    }
    pub fn finish(self: *Owner) !void {
        try self.columns.finish();
    }
    pub fn appendTo(self: *const Owner, comptime slot: usize, target: anytype) !void {
        try self.columns.appendTo(slot, target);
    }
    pub fn appendTrusted(self: *const Owner, comptime slot: usize, expected: *const FixedOwner, target: anytype) !void {
        const view = try self.columns.view(slot);
        const trusted = try expected.rows(slot);
        if (view.rowCount() != trusted.len) return error.InvalidNativeParentRows;
        for (view.fixed, trusted) |row, fixed| for (row, fixed) |actual, word| if (!actual.eql(word)) return error.InvalidNativeParentRows;
        try self.appendTo(slot, target);
    }
    /// Immediate indexed row access is used by fixed recipe/key fingerprint
    /// matching. A whole logical row roster is never returned.
    pub fn rowAt(self: *const Owner, comptime slot: usize, index: usize) !Storage.Airs[slot].Row {
        return self.columns.rowAt(slot, index);
    }
    pub fn rowCount(self: *const Owner, comptime slot: usize) usize {
        return self.columns.count(slot);
    }
};

/// Shared emission spelling keeps explicit row oracles while canonical
/// constructors send one transient row directly into the typed owner.
pub fn append(comptime slot: usize, sink: ?Sink, a: std.mem.Allocator, rows: *std.ArrayList(Storage.Airs[slot].Row), row: Storage.Airs[slot].Row, fixed: Storage.Airs[slot].Row) !void {
    if (sink) |out| try out.emit(slot, &row, &fixed) else try rows.append(a, row);
}

const FixedTuple = blk: {
    var types: [slots.len]type = undefined;
    for (slots, &types) |slot, *T| T.* = []Storage.FixedRow(Storage.Airs[slot]);
    break :blk std.meta.Tuple(&types);
};
/// Trusted preprocessing needs compact fixed tails only. It must not allocate
/// padded physical witness columns merely to fingerprint the source recipe.
pub const FixedOwner = struct {
    a: std.mem.Allocator,
    fixed: FixedTuple,
    next: [slots.len]usize = @splat(0),
    finished: bool = false,
    pub fn init(a: std.mem.Allocator, counts: Counts) !FixedOwner {
        var fixed: FixedTuple = undefined;
        inline for (slots, 0..) |_, index| fixed[index] = &.{};
        errdefer inline for (slots, 0..) |_, index| a.free(fixed[index]);
        inline for (slots, 0..) |slot, index| {
            if (counts.rows[index] > 1 << 24) return error.InvalidTraceShape;
            fixed[index] = try a.alloc(Storage.FixedRow(Storage.Airs[slot]), counts.rows[index]);
        }
        return .{ .a = a, .fixed = fixed };
    }
    pub fn deinit(self: *FixedOwner) void {
        inline for (slots, 0..) |_, index| self.a.free(self.fixed[index]);
        self.* = undefined;
    }
    pub fn sink(self: *FixedOwner) Sink {
        return .{ .context = self, .emit_row = emit, .add_coordinate = add, .row_count = count };
    }
    fn count(context: *anyopaque, tag: Tag) usize {
        const self: *FixedOwner = @ptrCast(@alignCast(context));
        return self.next[@intFromEnum(tag)];
    }
    fn emit(context: *anyopaque, row: RowRef, expected: RowRef) !void {
        const self: *FixedOwner = @ptrCast(@alignCast(context));
        if (self.finished or std.meta.activeTag(row) != std.meta.activeTag(expected)) return error.InvalidNativeParentRows;
        switch (row) {
            inline else => |value, tag| {
                const index = comptime @intFromEnum(tag);
                const slot = comptime slots[index];
                try validateFixed(slot, value, @field(expected, @tagName(tag)));
                if (self.next[index] >= self.fixed[index].len) return error.DirectRecursiveRowCountMismatch;
                self.fixed[index][self.next[index]] = Storage.compactFixed(Storage.Airs[slot], value.*);
                self.next[index] += 1;
            },
        }
    }
    fn add(context: *anyopaque, tag: Tag, index: usize, coordinate: usize, increment: u32) !void {
        const self: *FixedOwner = @ptrCast(@alignCast(context));
        const p = comptime position(15);
        if (self.finished or tag != .counter or self.next[p] == 0 or index >= self.next[p] or coordinate < 31 or coordinate > 32) return error.InvalidNonhashMultiplicityPatch;
        const value = &self.fixed[p][index][coordinate - Storage.Airs[15].PHYSICAL_MAIN_COLUMN_COUNT];
        const sum = try std.math.add(u32, value.v, increment);
        if (sum >= core.fields.m31.Modulus) return error.InvalidNonhashMultiplicityPatch;
        value.* = M.fromCanonical(sum);
    }
    pub fn finish(self: *FixedOwner) !void {
        if (self.finished) return error.InvalidUpstreamSourceColumns;
        inline for (slots, 0..) |_, index| if (self.next[index] != self.fixed[index].len) return error.DirectRecursiveRowCountMismatch;
        self.finished = true;
    }
    pub fn rows(self: *const FixedOwner, comptime slot: usize) ![]const Storage.FixedRow(Storage.Airs[slot]) {
        if (!self.finished) return error.InvalidUpstreamSourceColumns;
        return self.fixed[comptime position(slot)];
    }
};
