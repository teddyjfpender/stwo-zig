//! Verifier-derived signed multiplicity bounds for a joined SHA precompile.
//! Fixed topology and typed effects are the only counting authorities.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/mod.zig");
const profile = @import("sha256_component_profile.zig");
const preprocessing = @import("sha256_preprocessed.zig");
const schema = @import("../lookups/tables/schema.zig");

pub const Bounds = struct {
    tables: [schema.KIND_COUNT]u64 = @splat(0),
    memory_positive: u64 = 0,
    memory_negative: u64 = 0,
    /// Native memory admission already reserves three accesses per retirement.
    extra_memory_terms: u64 = 0,
};

pub fn derive(a: std.mem.Allocator, count: u32) !Bounds {
    return deriveForRecipe(false, a, count);
}
pub fn deriveForRecipe(comptime local_zero: bool, a: std.mem.Allocator, count: u32) !Bounds {
    const geometry = try profile.Geometry.init(count);
    const census = try setup_caches[@intFromBool(local_zero)].get(local_zero, a);
    var result = Bounds{};
    for (census, 0..) |entry, index| {
        const live_rows = try std.math.mul(u64, count, entry.pattern_rows);
        const padded_rows = @as(u64, 1) << @intCast(geometry.logs[index]);
        const padding = try std.math.sub(u64, padded_rows, live_rows);
        for (&result.tables, entry.per_call.tables, entry.padding.tables) |*target, live, padded| {
            target.* = try bounded(try std.math.add(u64, target.*, try scaled(count, live, padding, padded)));
        }
        result.memory_positive = try bounded(try std.math.add(u64, result.memory_positive, try scaled(count, entry.per_call.memory_positive, padding, entry.padding.memory_positive)));
        result.memory_negative = try bounded(try std.math.add(u64, result.memory_negative, try scaled(count, entry.per_call.memory_negative, padding, entry.padding.memory_negative)));
    }
    result.extra_memory_terms = @max(result.memory_positive, result.memory_negative) -| try std.math.mul(u64, count, 3);
    return result;
}
fn scaled(count: u32, live: u64, padding: u64, padded: u64) !u64 {
    return std.math.add(u64, try std.math.mul(u64, count, live), try std.math.mul(u64, padding, padded));
}
const CensusEntry = struct { pattern_rows: u64, per_call: Bounds = .{}, padding: Bounds = .{} };
const Census = [profile.AirsForRecipe(false).len]CensusEntry;
const CensusCache = struct {
    mutex: std.Thread.Mutex = .{},
    value: ?Census = null,
    successful_builds: usize = 0,
    fn get(self: *CensusCache, comptime local_zero: bool, a: std.mem.Allocator) !Census {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.value) |value| return value;
        // All scratch uses the caller's allocator and is destroyed before
        // publication. Failed initialization stays empty and can be retried.
        const value = try censusForRecipe(local_zero, a);
        self.value = value;
        self.successful_builds += 1;
        return value;
    }
};
// Recipe selects immutable compiled AIRs only. Counts, geometry and field
// bounds remain checked for every admission; no witness/challenge is cached.
var setup_caches: [2]CensusCache = .{ .{}, .{} };
fn censusForRecipe(comptime local_zero: bool, a: std.mem.Allocator) !Census {
    var result: Census = undefined;
    inline for (profile.AirsForRecipe(local_zero), 0..) |Air, index| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const pattern = try preprocessing.fixedPattern(index);
        result[index] = .{ .pattern_rows = pattern.len };
        for (definition.arena.effectsView()) |effect| {
            const binding = effect.binding orelse return error.InvalidShaBoundEffect;
            const kind = tableKind(binding.schema);
            const memory = binding.schema == lang.relation.id(.memory_access);
            if (kind == null and !memory) continue;
            const weight = effect.liveness orelse return error.UnboundedShaMultiplicity;
            var per_call: u64 = 0;
            for (pattern) |row| per_call = try std.math.add(u64, per_call, try multiplicityBound(Air, local_zero, &definition.arena, weight, row));
            const zero: [Air.PREPROCESSED_COLUMN_COUNT]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
            const padding = try multiplicityBound(Air, local_zero, &definition.arena, weight, zero);
            try addCensus(&result[index].per_call, kind, binding.role, per_call);
            try addCensus(&result[index].padding, kind, binding.role, padding);
        }
    }
    return result;
}
fn addCensus(target: *Bounds, kind: ?schema.Kind, role: anytype, weight: u64) !void {
    const value = if (kind) |table| blk: {
        if (role != .request) return error.InvalidShaBoundEffect;
        break :blk &target.tables[@intFromEnum(table)];
    } else switch (role) {
        .emit => &target.memory_positive,
        .consume, .request => &target.memory_negative,
    };
    value.* = try std.math.add(u64, value.*, weight);
}

/// Independent original effect-by-effect oracle. This builds actual typed AIR
/// definitions for each call, without reading or populating the setup cache.
pub fn deriveUncachedForRecipe(comptime local_zero: bool, a: std.mem.Allocator, count: u32) !Bounds {
    const geometry = try profile.Geometry.init(count);
    var result = Bounds{};
    inline for (profile.AirsForRecipe(local_zero), 0..) |Air, index| {
        var definition = try Air.build(a);
        defer definition.deinit();
        const pattern = try preprocessing.fixedPattern(index);
        const live_rows = try std.math.mul(u64, count, pattern.len);
        const padded_rows = @as(u64, 1) << @intCast(geometry.logs[index]);
        const padding = try std.math.sub(u64, padded_rows, live_rows);
        for (definition.arena.effectsView()) |effect| {
            const binding = effect.binding orelse return error.InvalidShaBoundEffect;
            const kind = tableKind(binding.schema);
            const memory = binding.schema == lang.relation.id(.memory_access);
            if (kind == null and !memory) continue;
            const weight = effect.liveness orelse return error.UnboundedShaMultiplicity;
            var per_call: u64 = 0;
            for (pattern) |row| per_call = try std.math.add(u64, per_call, try multiplicityBound(Air, local_zero, &definition.arena, weight, row));
            const zero: [Air.PREPROCESSED_COLUMN_COUNT]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
            const padding_weight = try multiplicityBound(Air, local_zero, &definition.arena, weight, zero);
            const terms = try std.math.add(u64, try std.math.mul(u64, count, per_call), try std.math.mul(u64, padding, padding_weight));
            if (kind) |table| {
                if (binding.role != .request) return error.InvalidShaBoundEffect;
                const target = &result.tables[@intFromEnum(table)];
                target.* = try bounded(try std.math.add(u64, target.*, terms));
            } else {
                const target = switch (binding.role) {
                    .emit => &result.memory_positive,
                    .consume, .request => &result.memory_negative,
                };
                target.* = try bounded(try std.math.add(u64, target.*, terms));
            }
        }
    }
    result.extra_memory_terms = @max(result.memory_positive, result.memory_negative) -| try std.math.mul(u64, count, 3);
    return result;
}

test "SHA admission setup cache: original uncached effect oracle agrees across padding geometry and rejection boundaries" {
    inline for (.{ false, true }) |local_zero| for ([_]u32{ 0, 1, 2, 7, 16, 64, 32768, 1 << 20, 1 << 24, std.math.maxInt(u32) }) |count| {
        const cached = deriveForRecipe(local_zero, std.testing.allocator, count);
        const original = deriveUncachedForRecipe(local_zero, std.testing.allocator, count);
        if (original) |expected| {
            try std.testing.expectEqualDeep(expected, try cached);
        } else |err| try std.testing.expectError(err, cached);
    };
}
test "SHA admission setup cache: failed initialization publishes nothing and warm setup performs no allocator calls" {
    var cache = CensusCache{};
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, cache.get(true, failing.allocator()));
    try std.testing.expect(cache.value == null);
    try std.testing.expectEqual(@as(usize, 0), cache.successful_builds);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    const original = try cache.get(true, std.testing.allocator);
    var no_allocations = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectEqualDeep(original, try cache.get(true, no_allocations.allocator()));
    try std.testing.expectEqual(@as(usize, 0), no_allocations.alloc_index);
    try std.testing.expect(!no_allocations.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), cache.successful_builds);
}
test "SHA admission setup cache: concurrent callers publish exactly one immutable actual typed census" {
    const Task = struct {
        cache: *CensusCache,
        value: ?Census = null,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.value = self.cache.get(false, std.heap.page_allocator) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    var cache = CensusCache{};
    var tasks = [_]Task{ .{ .cache = &cache }, .{ .cache = &cache }, .{ .cache = &cache } };
    var threads: [tasks.len]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&tasks, 0..) |*task, i| {
        threads[i] = try std.Thread.spawn(.{}, Task.run, .{task});
        started += 1;
    }
    for (threads[0..started]) |thread| thread.join();
    started = 0;
    for (tasks) |task| {
        if (task.failure) |err| return err;
        try std.testing.expect(task.value != null);
        try std.testing.expectEqualDeep(tasks[0].value.?, task.value.?);
    }
    try std.testing.expectEqual(@as(usize, 1), cache.successful_builds);
}

fn multiplicityBound(comptime Air: type, comptime local_zero: bool, arena: *const lang.ir.Arena, id: lang.types.ValueId, fixed: [Air.PREPROCESSED_COLUMN_COUNT]core.fields.m31.M31) !u64 {
    const node = arena.node(id) orelse return error.UnboundedShaMultiplicity;
    return switch (node.key.op) {
        .constant => |value| bounded(switch (value) {
            .field => |v| v,
            .unsigned => |v| v,
        }),
        .input => blk: {
            const index = lang.types.idIndex(id);
            if (local_zero and Air.PHYSICAL_MAIN_COLUMN_COUNT == @import("sha256_caller_local_zero_v1.zig").PHYSICAL_MAIN_COLUMN_COUNT and
                std.mem.eql(u8, &Air.SEMANTIC_DIGEST, &@import("sha256_caller_local_zero_v1.zig").SEMANTIC_DIGEST) and
                (index == @import("sha256_memory_caller.zig").PHYSICAL_MAIN_COLUMN_COUNT or index == @import("sha256_memory_caller.zig").PHYSICAL_MAIN_COLUMN_COUNT + 2))
                // Only authenticated Boolean nz hints have this public upper
                // bound. Addresses, inverses and arbitrary main inputs remain
                // inadmissible multiplicity authorities.
                break :blk 1;
            if (index < Air.PHYSICAL_MAIN_COLUMN_COUNT or index >= Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT) return error.UnboundedShaMultiplicity;
            break :blk bounded(fixed[index - Air.PHYSICAL_MAIN_COLUMN_COUNT].toU32());
        },
        .mul => |children| bounded(try std.math.mul(u64, try multiplicityBound(Air, local_zero, arena, children.lhs, fixed), try multiplicityBound(Air, local_zero, arena, children.rhs, fixed))),
        else => error.UnboundedShaMultiplicity,
    };
}

test "block-v5 selected production SHA bounds use authenticated local-zero multiplicities" {
    for ([_]u32{ 0, 1, 16 }) |count| {
        const original = try derive(std.testing.allocator, count);
        const selected = try deriveForRecipe(true, std.testing.allocator, count);
        // Runtime x0 rows can reduce actual demand; independently admitted
        // upper bounds still reserve every possible nonzero pointer.
        try std.testing.expectEqualDeep(original, selected);
    }
}

fn tableKind(id: lang.types.RelationSchemaId) ?schema.Kind {
    inline for (profile.lookup_kinds) |kind| if (id == lang.relation.id(@field(lang.relation.Domain, @tagName(kind)))) return kind;
    return null;
}
fn bounded(value: u64) !u64 {
    if (value >= core.fields.m31.Modulus) return error.CoefficientBoundExceeded;
    return value;
}

test "SHA provider public coefficient bounds include padding and both memory polarities" {
    for ([_]u32{ 0, 1, 16, 64 }) |count| {
        const bounds = try derive(std.testing.allocator, count);
        try std.testing.expectEqual(@as(u64, 26) * count, bounds.memory_positive);
        try std.testing.expectEqual(bounds.memory_positive, bounds.memory_negative);
        try std.testing.expectEqual(@as(u64, 23) * count, bounds.extra_memory_terms);
        try std.testing.expect(bounds.tables[@intFromEnum(schema.Kind.range_check_8_8)] != 0);
    }
}
