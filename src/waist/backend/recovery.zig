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

// Singleton compile-time causes preserve each operation's inferred error set.
// Callback and I/O catches must never pass through this owned projection.
fn ownedFailure(comptime cause: anytype, failure: ?*?@import("stwo_core").error_codes.Entry) @TypeOf(cause) {
    comptime {
        const tags = @typeInfo(@TypeOf(cause)).error_set orelse @compileError("owned cause must be a singleton");
        if (tags.len != 1) @compileError("owned cause must be a singleton");
    }
    if (failure) |sink| sink.* = @import("error_codes.zig").fromRecovery(cause);
    return cause;
}

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
        return self.spillDiagnosed(binding, source, null);
    }

    pub fn spillDiagnosed(self: *FileSpillStore, binding: arena_plan.Binding, source: []const u8, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        const spill_entry = self.findEntry(binding.logical_id) orelse return ownedFailure(error.MissingSpillEntry, failure);
        if (source.len != spill_entry.size or binding.size_bytes != spill_entry.size) return ownedFailure(error.BindingSizeMismatch, failure);
        try self.file.pwriteAll(source, spill_entry.offset);
        spill_entry.checksum = std.hash.Wyhash.hash(binding.logical_id, source);
        spill_entry.materialized = true;
        self.bytes_written += source.len;
    }

    pub fn restore(self: *FileSpillStore, binding: arena_plan.Binding, destination: []u8) !void {
        return self.restoreDiagnosed(binding, destination, null);
    }

    /// A failed read/checksum invalidates destination contents; no retry is implicit.
    pub fn restoreDiagnosed(self: *FileSpillStore, binding: arena_plan.Binding, destination: []u8, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        const spill_entry = self.findEntry(binding.logical_id) orelse return ownedFailure(error.MissingSpillEntry, failure);
        if (!spill_entry.materialized) return ownedFailure(error.SpillNotMaterialized, failure);
        if (destination.len != spill_entry.size or binding.size_bytes != spill_entry.size) return ownedFailure(error.BindingSizeMismatch, failure);
        if (try self.file.preadAll(destination, spill_entry.offset) != destination.len) return error.EndOfStream;
        if (std.hash.Wyhash.hash(binding.logical_id, destination) != spill_entry.checksum) return ownedFailure(error.SpillCorrupted, failure);
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
        return initDiagnosed(allocator, input, null);
    }

    pub fn initDiagnosed(allocator: std.mem.Allocator, input: []const Recipe, failure: ?*?@import("stwo_core").error_codes.Entry) !RecipeRegistry {
        if (failure) |sink| sink.* = null;
        const recipes = try allocator.dupe(Recipe, input);
        errdefer allocator.free(recipes);
        std.mem.sortUnstable(Recipe, recipes, {}, lessThan);
        if (recipes.len > 1) for (recipes[1..], recipes[0 .. recipes.len - 1]) |current, previous| {
            if (current.logical_id == previous.logical_id) return ownedFailure(error.DuplicateRecipe, failure);
        };
        return .{ .allocator = allocator, .recipes = recipes };
    }

    pub fn deinit(self: *RecipeRegistry) void {
        self.allocator.free(self.recipes);
        self.* = undefined;
    }

    pub fn execute(self: RecipeRegistry, tick: u16, binding: arena_plan.Binding, destination: []u8) !void {
        return self.executeDiagnosed(tick, binding, destination, null);
    }

    pub fn executeDiagnosed(self: RecipeRegistry, tick: u16, binding: arena_plan.Binding, destination: []u8, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        const recipe = self.find(binding.logical_id) orelse return ownedFailure(error.MissingRecipe, failure);
        if (destination.len != binding.size_bytes) return ownedFailure(error.BindingSizeMismatch, failure);
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
        return self.validatePlanDiagnosed(plan, null);
    }

    pub fn validatePlanDiagnosed(self: RecoveryEngine, plan: arena_plan.Plan, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        for (plan.bindings) |binding| switch (binding.materialization) {
            .resident => {},
            .spill => if (!self.spill_store.contains(binding.logical_id)) return ownedFailure(error.MissingSpillEntry, failure),
            .recompute => if (!self.recipes.contains(binding.logical_id)) return ownedFailure(error.MissingRecipe, failure),
        };
    }

    pub fn spillDiagnosed(self: *RecoveryEngine, binding: arena_plan.Binding, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        try self.spill_store.spillDiagnosed(binding, try self.access.bytes(binding), failure);
    }

    pub fn restoreDiagnosed(self: *RecoveryEngine, binding: arena_plan.Binding, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        try self.spill_store.restoreDiagnosed(binding, try self.access.bytes(binding), failure);
    }

    pub fn recomputeDiagnosed(self: *RecoveryEngine, tick: u16, binding: arena_plan.Binding, failure: ?*?@import("stwo_core").error_codes.Entry) !void {
        if (failure) |sink| sink.* = null;
        try self.recipes.executeDiagnosed(tick, binding, try self.access.bytes(binding), failure);
    }

    fn spillHook(raw: *anyopaque, _: u16, binding: arena_plan.Binding) !void {
        const self: *RecoveryEngine = @ptrCast(@alignCast(raw));
        try self.spillDiagnosed(binding, null);
    }

    fn restoreHook(raw: *anyopaque, _: u16, binding: arena_plan.Binding) !void {
        const self: *RecoveryEngine = @ptrCast(@alignCast(raw));
        try self.restoreDiagnosed(binding, null);
    }

    fn recomputeHook(raw: *anyopaque, tick: u16, binding: arena_plan.Binding) !void {
        const self: *RecoveryEngine = @ptrCast(@alignCast(raw));
        try self.recomputeDiagnosed(tick, binding, null);
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

test "recovery: empty recipe registry admits resident-only planning" {
    var registry = try RecipeRegistry.init(std.testing.allocator, &.{});
    defer registry.deinit();
    try std.testing.expectEqual(@as(usize, 0), registry.recipes.len);
    try std.testing.expect(!registry.contains(0));
    const logical = [_]arena_plan.LogicalBuffer{.{ .id = 1, .size_bytes = 8, .alignment = 16, .live_ranges = &.{.{ .first = 0, .last = 1 }} }};
    var plan = try arena_plan.build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();
    try std.testing.expectEqual(arena_plan.Materialization.resident, (try plan.binding(1)).materialization);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const file = try temporary.dir.createFile("resident.bin", .{ .read = true });
    var store = try FileSpillStore.init(std.testing.allocator, file, true, plan);
    defer store.deinit();
    const Guard = struct {
        fn get(_: *anyopaque, _: arena_plan.Binding) ![]u8 {
            return error.ResidentPlanMustNotAccessRecoveryStorage;
        }
    };
    var marker: u8 = 0;
    const engine = RecoveryEngine{ .access = .{ .context = &marker, .bytes_fn = Guard.get }, .spill_store = &store, .recipes = &registry };
    var failure: ?@import("stwo_core").error_codes.Entry = @import("error_codes.zig").fromRecovery(error.MissingRecipe);
    try engine.validatePlanDiagnosed(plan, &failure);
    try std.testing.expect(failure == null);
}

test "recovery diagnostics preserve owned registry failures and foreign callback provenance" {
    const C = @import("error_codes.zig");
    const Entry = @import("stwo_core").error_codes.Entry;
    const Context = struct {
        cause: ?RecoveryError = null,
        bytes: [8]u8 = @splat(0),
        fn run(raw: *anyopaque, _: u16, _: arena_plan.Binding, out: []u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.cause) |cause| return cause;
            @memset(out, 0x5a);
        }
    };
    var context: Context = .{};
    const recipe = Recipe{ .logical_id = 9, .context = &context, .run = Context.run };
    var failure: ?Entry = null;
    try std.testing.expectError(error.DuplicateRecipe, RecipeRegistry.initDiagnosed(std.testing.allocator, &.{ recipe, recipe }, &failure));
    try std.testing.expectEqual(@as(u16, 0x2401), failure.?.code);
    var registry = try RecipeRegistry.initDiagnosed(std.testing.allocator, &.{recipe}, &failure);
    defer registry.deinit();
    try std.testing.expect(failure == null);
    const binding = arena_plan.Binding{ .logical_id = 9, .slot = 0, .offset_bytes = 0, .size_bytes = 8, .materialization = .recompute, .occupied = @splat(0) };
    var missing = binding;
    missing.logical_id = 10;
    try std.testing.expectError(error.MissingRecipe, registry.executeDiagnosed(1, missing, &context.bytes, &failure));
    try std.testing.expectEqual(@as(u16, 0x2402), failure.?.code);
    try std.testing.expectError(error.BindingSizeMismatch, registry.executeDiagnosed(1, binding, context.bytes[0..7], &failure));
    try std.testing.expectEqual(@as(u16, 0x2406), failure.?.code);
    for ([_]RecoveryError{ error.DuplicateRecipe, error.MissingRecipe, error.MissingSpillEntry, error.SpillNotMaterialized, error.SpillCorrupted, error.BindingSizeMismatch }) |cause| {
        context.cause = cause;
        failure = C.fromRecovery(error.DuplicateRecipe);
        try std.testing.expectError(cause, registry.executeDiagnosed(1, binding, &context.bytes, &failure));
        try std.testing.expect(failure == null);
    }
    context.cause = null;
    try registry.executeDiagnosed(1, binding, &context.bytes, &failure);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x5a} ** 8), &context.bytes);
    try std.testing.expect(failure == null);
    const Runner = struct {
        fn run(a: std.mem.Allocator, item: Recipe) !void {
            var detail: ?Entry = C.fromRecovery(error.MissingRecipe);
            var owned = RecipeRegistry.initDiagnosed(a, &.{item}, &detail) catch |err| {
                try std.testing.expect(detail == null);
                return err;
            };
            defer owned.deinit();
            try std.testing.expect(detail == null);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Runner.run, .{recipe});
}

test "recovery diagnostics execute real spill corruption and retain uncoded file failures" {
    const Entry = @import("stwo_core").error_codes.Entry;
    const logical = [_]arena_plan.LogicalBuffer{.{ .id = 7, .size_bytes = 32, .alignment = 16, .live_ranges = &.{ .{ .first = 1, .last = 1 }, .{ .first = 2, .last = 2 } }, .spill_cost_ns = 1 }};
    var plan = try arena_plan.build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const file = try temporary.dir.createFile("diagnosed.bin", .{ .read = true });
    var store = try FileSpillStore.init(std.testing.allocator, file, true, plan);
    defer store.deinit();
    const binding = try plan.binding(7);
    var source: [32]u8 = @splat(0x33);
    var destination: [32]u8 = @splat(0);
    var failure: ?Entry = null;
    try std.testing.expectError(error.SpillNotMaterialized, store.restoreDiagnosed(binding, &destination, &failure));
    try std.testing.expectEqual(@as(u16, 0x2404), failure.?.code);
    var missing = binding;
    missing.logical_id = 8;
    try std.testing.expectError(error.MissingSpillEntry, store.spillDiagnosed(missing, &source, &failure));
    try std.testing.expectEqual(@as(u16, 0x2403), failure.?.code);
    try std.testing.expectError(error.BindingSizeMismatch, store.spillDiagnosed(binding, source[0..31], &failure));
    try std.testing.expectEqual(@as(u16, 0x2406), failure.?.code);
    try std.testing.expectEqual(@as(u64, 0), store.bytes_written);
    try store.spillDiagnosed(binding, &source, &failure);
    try std.testing.expect(failure == null);
    try store.restoreDiagnosed(binding, &destination, &failure);
    try std.testing.expectEqualSlices(u8, &source, &destination);
    try std.testing.expect(failure == null);
    try store.file.pwriteAll(&.{0xff}, 0);
    try std.testing.expectError(error.SpillCorrupted, store.restoreDiagnosed(binding, &destination, &failure));
    try std.testing.expectEqual(@as(u16, 0x2405), failure.?.code);
    try std.testing.expectEqual(@as(u64, 32), store.bytes_read);
    try store.file.setEndPos(0);
    try std.testing.expectError(error.EndOfStream, store.restoreDiagnosed(binding, &destination, &failure));
    try std.testing.expect(failure == null);
}

test "recovery diagnostics follow actual engine hooks and keep buffer errors foreign" {
    const C = @import("error_codes.zig");
    const Context = struct {
        storage: [8]u8 = @splat(0x55),
        access_error: ?RecoveryError = null,
        recipe_error: ?RecoveryError = null,
        fn get(raw: *anyopaque, _: arena_plan.Binding) ![]u8 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.access_error) |cause| return cause;
            return &self.storage;
        }
        fn run(raw: *anyopaque, _: u16, _: arena_plan.Binding, out: []u8) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.recipe_error) |cause| return cause;
            @memset(out, 0x5a);
        }
    };
    const logical = [_]arena_plan.LogicalBuffer{.{ .id = 7, .size_bytes = 8, .alignment = 16, .live_ranges = &.{ .{ .first = 1, .last = 1 }, .{ .first = 2, .last = 2 } }, .spill_cost_ns = 1 }};
    var plan = try arena_plan.build(std.testing.allocator, &logical, 16 * 1024);
    defer plan.deinit();
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const file = try temporary.dir.createFile("hooks.bin", .{ .read = true });
    var store = try FileSpillStore.init(std.testing.allocator, file, true, plan);
    defer store.deinit();
    var context: Context = .{};
    var registry = try RecipeRegistry.init(std.testing.allocator, &.{.{ .logical_id = 7, .context = &context, .run = Context.run }});
    defer registry.deinit();
    var engine = RecoveryEngine{ .access = .{ .context = &context, .bytes_fn = Context.get }, .spill_store = &store, .recipes = &registry };
    var failure: ?@import("stwo_core").error_codes.Entry = C.fromRecovery(error.SpillCorrupted);
    try engine.validatePlanDiagnosed(plan, &failure);
    try std.testing.expect(failure == null);
    const binding = try plan.binding(7);
    const hooks = engine.hooks();
    try hooks.spill(hooks.context, 1, binding);
    @memset(&context.storage, 0);
    try engine.restoreDiagnosed(binding, &failure);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x55} ** 8), &context.storage);
    try hooks.recompute(hooks.context, 2, binding);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x5a} ** 8), &context.storage);
    for ([_]RecoveryError{ error.DuplicateRecipe, error.MissingRecipe, error.MissingSpillEntry, error.SpillNotMaterialized, error.SpillCorrupted, error.BindingSizeMismatch }) |cause| {
        context.access_error = cause;
        failure = C.fromRecovery(error.MissingRecipe);
        try std.testing.expectError(cause, engine.spillDiagnosed(binding, &failure));
        try std.testing.expect(failure == null);
        try std.testing.expectError(cause, engine.restoreDiagnosed(binding, &failure));
        try std.testing.expect(failure == null);
        try std.testing.expectError(cause, engine.recomputeDiagnosed(3, binding, &failure));
        try std.testing.expect(failure == null);
        context.access_error = null;
        context.recipe_error = cause;
        try std.testing.expectError(cause, engine.recomputeDiagnosed(3, binding, &failure));
        try std.testing.expect(failure == null);
    }
    var absent = [_]arena_plan.Binding{binding};
    absent[0].logical_id = 8;
    var invalid = plan;
    invalid.bindings = &absent;
    try std.testing.expectError(error.MissingSpillEntry, engine.validatePlanDiagnosed(invalid, &failure));
    try std.testing.expectEqual(@as(u16, 0x2403), failure.?.code);
    absent[0].materialization = .recompute;
    try std.testing.expectError(error.MissingRecipe, engine.validatePlanDiagnosed(invalid, &failure));
    try std.testing.expectEqual(@as(u16, 0x2402), failure.?.code);
}
