//! Capacity planning for separately proved block components.
//! Counts are actual typed-AIR rows, not guest instructions. Planning is not
//! proof admission: the final protocol must bind every instance and close its
//! cross-component relations. No execution proof is activated by this module.
const std = @import("std");
/// Stable tags used by the versioned block commitment manifest.
pub const Kind = enum(u8) { execution = 0, memory = 1, program = 2, keccak = 3, sha256 = 4, secp256k1 = 5, range = 6 };
pub const Family = struct {
    kind: Kind,
    rows: u64,
    /// Columns resident for the caller's chosen stage. Does not include PCS,
    /// recursion or allocator scratch; that remains under the runtime budget.
    columns: u32,
    /// Supported heights of one AIR family with the same column layout.
    log_rows: []const u8,
};
pub const Limits = struct { source_bytes_per_instance: u64, max_instances: u32 };
pub const Instance = struct {
    index: u32,
    kind: Kind,
    first_row: u64,
    rows: u64,
    log_rows: u8,
    source_bytes: u64,
    pub fn capacity(self: Instance) u64 {
        return @as(u64, 1) << @intCast(self.log_rows);
    }
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    instances: []Instance,
    source_bytes: u64,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.instances);
        self.* = undefined;
    }
};
/// Minimize instance count per family, then allocated rows. Heights are powers
/// of two; the number of instances is not rounded. Empty families emit no work.
pub fn create(a: std.mem.Allocator, families: []const Family, limits: Limits) !Plan {
    var out: std.ArrayList(Instance) = .empty;
    errdefer out.deinit(a);
    var seen = std.EnumSet(Kind).initEmpty();
    var total_bytes: u64 = 0;
    for (families) |family| {
        if (seen.contains(family.kind)) return error.DuplicateComponentFamily;
        seen.insert(family.kind);
        if (family.columns == 0 or family.log_rows.len == 0) return error.InvalidComponentGeometry;
        var available: [30]u8 = undefined;
        var available_count: usize = 0;
        var previous: u8 = 0;
        for (family.log_rows) |log| {
            if (log == 0 or log > 30 or log <= previous) return error.InvalidComponentGeometry;
            previous = log;
            if (try sourceBytes(family.columns, log) <= limits.source_bytes_per_instance) {
                available[available_count] = log;
                available_count += 1;
            }
        }
        if (family.rows == 0) continue;
        if (available_count == 0) return error.ComponentDoesNotFitSourceBudget;
        const largest: u64 = @as(u64, 1) << @intCast(available[available_count - 1]);
        const count = try std.math.divCeil(u64, family.rows, largest);
        if (count > limits.max_instances or out.items.len > limits.max_instances - count) return error.TooManyComponentInstances;
        var first: u64 = 0;
        for (0..@as(usize, @intCast(count))) |i| {
            const left = family.rows - first;
            const after = count - i - 1;
            const required = @max(1, left -| try std.math.mul(u64, after, largest));
            var chosen = available[available_count - 1];
            for (available[0..available_count]) |log| {
                if (@as(u64, 1) << @intCast(log) >= required) {
                    chosen = log;
                    break;
                }
            }
            const capacity: u64 = @as(u64, 1) << @intCast(chosen);
            const rows = @min(capacity, left - after);
            const bytes = try sourceBytes(family.columns, chosen);
            total_bytes = try std.math.add(u64, total_bytes, bytes);
            try out.append(a, .{ .index = @intCast(out.items.len), .kind = family.kind, .first_row = first, .rows = rows, .log_rows = chosen, .source_bytes = bytes });
            first += rows;
        }
        std.debug.assert(first == family.rows);
    }
    return .{ .allocator = a, .instances = try out.toOwnedSlice(a), .source_bytes = total_bytes };
}
fn sourceBytes(columns: u32, log: u8) !u64 {
    return std.math.mul(u64, @as(u64, columns) * 4, @as(u64, 1) << @intCast(log));
}

test "component instances cover arbitrary counts without power-of-two rounding" {
    var plan = try create(std.testing.allocator, &.{.{ .kind = .memory, .rows = 9, .columns = 8, .log_rows = &.{ 1, 2 } }}, .{ .source_bytes_per_instance = 128, .max_instances = 3 });
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 3), plan.instances.len);
    try std.testing.expectEqual(@as(u64, 320), plan.source_bytes);
    var next: u64 = 0;
    for (plan.instances, 0..) |item, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), item.index);
        try std.testing.expectEqual(next, item.first_row);
        try std.testing.expect(item.rows > 0 and item.rows <= item.capacity());
        next += item.rows;
    }
    try std.testing.expectEqual(@as(u64, 9), next);
}
test "component families size independently and inactive precompiles allocate nothing" {
    var plan = try create(std.testing.allocator, &.{
        .{ .kind = .execution, .rows = 10, .columns = 8, .log_rows = &.{ 1, 2, 3 } },
        .{ .kind = .memory, .rows = 3, .columns = 16, .log_rows = &.{ 1, 2, 3 } },
        .{ .kind = .sha256, .rows = 0, .columns = 32, .log_rows = &.{2} },
    }, .{ .source_bytes_per_instance = 256, .max_instances = 4 });
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 3), plan.instances.len);
    try std.testing.expectEqual(Kind.execution, plan.instances[0].kind);
    try std.testing.expectEqual(Kind.memory, plan.instances[2].kind);
    try std.testing.expectEqual(@as(u64, 0), plan.instances[2].first_row);
    try std.testing.expectEqual(@as(u8, 2), plan.instances[2].log_rows);
}
test "component planner rejects unsupported capacity and duplicate families" {
    const family = Family{ .kind = .memory, .rows = 9, .columns = 8, .log_rows = &.{ 1, 2 } };
    try std.testing.expectError(error.ComponentDoesNotFitSourceBudget, create(std.testing.allocator, &.{family}, .{ .source_bytes_per_instance = 1, .max_instances = 9 }));
    try std.testing.expectError(error.TooManyComponentInstances, create(std.testing.allocator, &.{family}, .{ .source_bytes_per_instance = 128, .max_instances = 2 }));
    try std.testing.expectError(error.DuplicateComponentFamily, create(std.testing.allocator, &.{ family, family }, .{ .source_bytes_per_instance = 128, .max_instances = 9 }));
}
