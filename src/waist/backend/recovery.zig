const std = @import("std");
const arena_plan = @import("arena_plan.zig");

pub const RecoveryError = error{
    DuplicateRecipe,
    MissingRecipe,
    MissingSpillEntry,
    SpillNotMaterialized,
    SpillCorrupted,
    BindingSizeMismatch,
};

/// Type-erased access to storage owned by a concrete backend.
pub const BufferAccess = struct {
    context: *anyopaque,
    bytes_fn: *const fn (*anyopaque, arena_plan.Binding) anyerror![]u8,

    pub fn bytes(self: BufferAccess, binding: arena_plan.Binding) ![]u8 {
        return self.bytes_fn(self.context, binding);
    }
};

const SpillEntry = struct {
    logical_id: u32,
    offset: u64,
    size: u64,
    checksum: u64 = 0,
    materialized: bool = false,
};

/// Preallocated, page-aligned, sparse-file backing for irreducible values.
/// Offsets are deterministic and no allocation occurs on the spill hot path.
pub const FileSpillStore = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    owns_file: bool,
    entries: []SpillEntry,
    capacity_bytes: u64,
    bytes_written: u64 = 0,
    bytes_read: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        file: std.fs.File,
        owns_file: bool,
        plan: arena_plan.Plan,
    ) !FileSpillStore {
        var count: usize = 0;
        for (plan.bindings) |binding| {
            if (binding.materialization == .spill) count += 1;
        }
        const entries = try allocator.alloc(SpillEntry, count);
        errdefer allocator.free(entries);
        var offset: u64 = 0;
        var index: usize = 0;
        for (plan.bindings) |binding| {
            if (binding.materialization != .spill) continue;
            offset = try alignForward(offset, 4096);
            entries[index] = .{ .logical_id = binding.logical_id, .offset = offset, .size = binding.size_bytes };
            offset = std.math.add(u64, offset, binding.size_bytes) catch return error.SizeOverflow;
            index += 1;
        }
        try file.setEndPos(offset);
        return .{
            .allocator = allocator,
            .file = file,
            .owns_file = owns_file,
            .entries = entries,
            .capacity_bytes = offset,
        };
    }

    pub fn deinit(self: *FileSpillStore) void {
        if (self.owns_file) self.file.close();
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn spill(self: *FileSpillStore, binding: arena_plan.Binding, source: []const u8) !void {
        const spill_entry = self.findEntry(binding.logical_id) orelse return RecoveryError.MissingSpillEntry;
        if (source.len != spill_entry.size or binding.size_bytes != spill_entry.size) return RecoveryError.BindingSizeMismatch;
        try self.file.pwriteAll(source, spill_entry.offset);
        spill_entry.checksum = std.hash.Wyhash.hash(binding.logical_id, source);
        spill_entry.materialized = true;
        self.bytes_written += source.len;
    }

    pub fn restore(self: *FileSpillStore, binding: arena_plan.Binding, destination: []u8) !void {
        const spill_entry = self.findEntry(binding.logical_id) orelse return RecoveryError.MissingSpillEntry;
        if (!spill_entry.materialized) return RecoveryError.SpillNotMaterialized;
        if (destination.len != spill_entry.size or binding.size_bytes != spill_entry.size) return RecoveryError.BindingSizeMismatch;
        if (try self.file.preadAll(destination, spill_entry.offset) != destination.len) return error.EndOfStream;
        if (std.hash.Wyhash.hash(binding.logical_id, destination) != spill_entry.checksum) return RecoveryError.SpillCorrupted;
        self.bytes_read += destination.len;
    }

    fn findEntry(self: *FileSpillStore, logical_id: u32) ?*SpillEntry {
        var low: usize = 0;
        var high = self.entries.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.entries[middle].logical_id < logical_id) low = middle + 1 else high = middle;
        }
        return if (low < self.entries.len and self.entries[low].logical_id == logical_id) &self.entries[low] else null;
    }

    pub fn contains(self: *FileSpillStore, logical_id: u32) bool {
        return self.findEntry(logical_id) != null;
    }
};

pub const Recipe = struct {
    logical_id: u32,
    context: *anyopaque,
    run: *const fn (*anyopaque, u16, arena_plan.Binding, []u8) anyerror!void,
};

pub const RecipeRegistry = struct {
    allocator: std.mem.Allocator,
    recipes: []Recipe,

    pub fn init(allocator: std.mem.Allocator, input: []const Recipe) !RecipeRegistry {
        const recipes = try allocator.dupe(Recipe, input);
        errdefer allocator.free(recipes);
        std.mem.sortUnstable(Recipe, recipes, {}, lessThan);
        for (recipes[1..], recipes[0 .. recipes.len - 1]) |current, previous| {
            if (current.logical_id == previous.logical_id) return RecoveryError.DuplicateRecipe;
        }
        return .{ .allocator = allocator, .recipes = recipes };
    }

    pub fn deinit(self: *RecipeRegistry) void {
        self.allocator.free(self.recipes);
        self.* = undefined;
    }

    pub fn execute(self: RecipeRegistry, tick: u16, binding: arena_plan.Binding, destination: []u8) !void {
        const recipe = self.find(binding.logical_id) orelse return RecoveryError.MissingRecipe;
        if (destination.len != binding.size_bytes) return RecoveryError.BindingSizeMismatch;
        try recipe.run(recipe.context, tick, binding, destination);
    }

    fn find(self: RecipeRegistry, logical_id: u32) ?Recipe {
        var low: usize = 0;
        var high = self.recipes.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.recipes[middle].logical_id < logical_id) low = middle + 1 else high = middle;
        }
        return if (low < self.recipes.len and self.recipes[low].logical_id == logical_id) self.recipes[low] else null;
    }

    pub fn contains(self: RecipeRegistry, logical_id: u32) bool {
        return self.find(logical_id) != null;
    }

    fn lessThan(_: void, left: Recipe, right: Recipe) bool {
        return left.logical_id < right.logical_id;
    }
};

/// Coalesces a multi-output operation behind every logical output id. The
/// operation is dispatched once per schedule tick even though the arena owns
/// each output independently.
pub const GroupRecipe = struct {
    allocator: std.mem.Allocator,
    access: BufferAccess,
    bindings: []const arena_plan.Binding,
    context: *anyopaque,
    dispatch_fn: *const fn (*anyopaque, u16, []const arena_plan.Binding, BufferAccess) anyerror!void,
    last_tick: ?u16 = null,
    dispatch_count: u64 = 0,

    pub fn makeRecipes(self: *GroupRecipe, allocator: std.mem.Allocator) ![]Recipe {
        const recipes = try allocator.alloc(Recipe, self.bindings.len);
        for (self.bindings, recipes) |binding, *recipe_entry| {
            recipe_entry.* = .{ .logical_id = binding.logical_id, .context = self, .run = run };
        }
        return recipes;
    }

    fn run(raw: *anyopaque, tick: u16, requested: arena_plan.Binding, _: []u8) !void {
        const self: *GroupRecipe = @ptrCast(@alignCast(raw));
        if (self.last_tick == tick) return;
        var found = false;
        for (self.bindings) |binding| found = found or binding.logical_id == requested.logical_id;
        if (!found) return RecoveryError.MissingRecipe;
        try self.dispatch_fn(self.context, tick, self.bindings, self.access);
        self.last_tick = tick;
        self.dispatch_count += 1;
    }
};

/// Concrete implementation of the arena epoch hooks. Spill and recomputation
/// both write directly into the binding's resident destination.
pub const RecoveryEngine = struct {
    access: BufferAccess,
    spill_store: *FileSpillStore,
    recipes: *const RecipeRegistry,

    pub fn hooks(self: *RecoveryEngine) arena_plan.RecoveryHooks {
        return .{
            .context = self,
            .spill = spillHook,
            .restore = restoreHook,
            .recompute = recomputeHook,
        };
    }

    /// Must pass before the resident slab is allocated or any proof command is
    /// submitted. A planned recomputation without an exact recipe is fatal.
    pub fn validatePlan(self: RecoveryEngine, plan: arena_plan.Plan) !void {
        for (plan.bindings) |binding| switch (binding.materialization) {
            .resident => {},
            .spill => if (!self.spill_store.contains(binding.logical_id)) return RecoveryError.MissingSpillEntry,
            .recompute => if (!self.recipes.contains(binding.logical_id)) return RecoveryError.MissingRecipe,
        };
    }

    fn spillHook(raw: *anyopaque, _: u16, binding: arena_plan.Binding) !void {
        const self: *RecoveryEngine = @ptrCast(@alignCast(raw));
        try self.spill_store.spill(binding, try self.access.bytes(binding));
    }

    fn restoreHook(raw: *anyopaque, _: u16, binding: arena_plan.Binding) !void {
        const self: *RecoveryEngine = @ptrCast(@alignCast(raw));
        try self.spill_store.restore(binding, try self.access.bytes(binding));
    }

    fn recomputeHook(raw: *anyopaque, tick: u16, binding: arena_plan.Binding) !void {
        const self: *RecoveryEngine = @ptrCast(@alignCast(raw));
        try self.recipes.execute(tick, binding, try self.access.bytes(binding));
    }
};

fn alignForward(value: u64, alignment: u64) !u64 {
    const mask = alignment - 1;
    return (std.math.add(u64, value, mask) catch return error.SizeOverflow) & ~mask;
}

test "recovery: aligned spill roundtrip and corruption detection" {
    const ranges = [_]arena_plan.LiveRange{ .{ .first = 1, .last = 1 }, .{ .first = 2, .last = 2 } };
    const logical = [_]arena_plan.LogicalBuffer{
        .{ .id = 7, .size_bytes = 32, .alignment = 16, .live_ranges = &ranges, .spill_cost_ns = 1 },
    };
    var plan = try arena_plan.build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const file = try temporary.dir.createFile("spill.bin", .{ .read = true, .truncate = true });
    var store = try FileSpillStore.init(std.testing.allocator, file, true, plan);
    defer store.deinit();
    const binding = try plan.binding(7);
    var source: [32]u8 = undefined;
    for (&source, 0..) |*byte, i| byte.* = @intCast(i);
    try store.spill(binding, &source);
    var restored = [_]u8{0} ** 32;
    try store.restore(binding, &restored);
    try std.testing.expectEqualSlices(u8, &source, &restored);
    try std.testing.expectEqual(@as(u64, 32), store.bytes_written);
    try std.testing.expectEqual(@as(u64, 32), store.bytes_read);
    try store.file.pwriteAll(&[_]u8{0xff}, 0);
    try std.testing.expectError(RecoveryError.SpillCorrupted, store.restore(binding, &restored));
}

test "recovery: recipe registry is fail closed" {
    const Context = struct {
        fn fill(_: *anyopaque, _: u16, _: arena_plan.Binding, destination: []u8) !void {
            @memset(destination, 0x5a);
        }
    };
    var registry = try RecipeRegistry.init(std.testing.allocator, &.{.{ .logical_id = 9, .context = undefined, .run = Context.fill }});
    defer registry.deinit();
    var destination = [_]u8{0} ** 8;
    const binding = arena_plan.Binding{
        .logical_id = 9,
        .slot = 0,
        .offset_bytes = 0,
        .size_bytes = destination.len,
        .materialization = .recompute,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };
    try registry.execute(1, binding, &destination);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x5a} ** 8), &destination);
    var missing = binding;
    missing.logical_id = 10;
    try std.testing.expectError(RecoveryError.MissingRecipe, registry.execute(1, missing, &destination));
}

test "recovery: grouped operation dispatches once per tick" {
    const Context = struct {
        calls: usize = 0,
        fn dispatch(raw: *anyopaque, _: u16, _: []const arena_plan.Binding, _: BufferAccess) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
        }
        fn bytes(_: *anyopaque, binding: arena_plan.Binding) ![]u8 {
            const storage = struct {
                var bytes_value: [8]u8 = [_]u8{0} ** 8;
            };
            return storage.bytes_value[0..binding.size_bytes];
        }
    };
    const occupied = [_]u64{0} ** (arena_plan.max_ticks / 64);
    const bindings = [_]arena_plan.Binding{
        .{ .logical_id = 1, .slot = 0, .offset_bytes = 0, .size_bytes = 4, .materialization = .recompute, .occupied = occupied },
        .{ .logical_id = 2, .slot = 1, .offset_bytes = 4, .size_bytes = 4, .materialization = .recompute, .occupied = occupied },
    };
    var context = Context{};
    var grouped = GroupRecipe{
        .allocator = std.testing.allocator,
        .access = .{ .context = &context, .bytes_fn = Context.bytes },
        .bindings = &bindings,
        .context = &context,
        .dispatch_fn = Context.dispatch,
    };
    const recipes = try grouped.makeRecipes(std.testing.allocator);
    defer std.testing.allocator.free(recipes);
    var registry = try RecipeRegistry.init(std.testing.allocator, recipes);
    defer registry.deinit();
    var destination = [_]u8{0} ** 4;
    try registry.execute(9, bindings[0], &destination);
    try registry.execute(9, bindings[1], &destination);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try registry.execute(10, bindings[0], &destination);
    try std.testing.expectEqual(@as(usize, 2), context.calls);
}
