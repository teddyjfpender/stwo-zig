//! SHA component rows borrowed from the single native execution tape.
//! The surrounding VM roster must close the caller's program/state/memory buses.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const provider = @import("sha256_compression_rows.zig");
const caller = @import("sha256_memory_caller.zig");
const profile = @import("sha256_component_profile.zig");
const native = @import("../../runner/guest_precompile/sha256_compression_v1.zig");
const contract = @import("../../isa/sha256_compression_v1.zig");

pub const Airs = profile.Airs;
pub const names = profile.names;
pub const Roster = profile.Roster;
pub const Geometry = profile.Geometry;

pub const Rows = RowsForRecipe(false);
pub const LocalZeroRows = RowsForRecipe(true);
pub fn RowsForRecipe(comptime local_zero: bool) type {
    const Caller = if (local_zero) @import("sha256_caller_local_zero_v1.zig") else caller;
    return struct {
        pub const local_zero_custody = local_zero;
        allocator: std.mem.Allocator,
        geometry: Geometry,
        compression: provider.Rows,
        callers: []Caller.Row,
        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.callers);
            self.compression.deinit();
            self.* = undefined;
        }
        pub fn tuple(self: @This()) @TypeOf(self.compression.tuple() ++ .{self.callers}) {
            return self.compression.tuple() ++ .{self.callers};
        }
    };
}

pub fn preflight(entries: []const native.Entry, total_steps: u32) !void {
    var previous: u32 = 0;
    for (entries) |entry| {
        const call = entry.call;
        if (call.execution_clock <= previous or call.execution_clock > total_steps) return error.InvalidShaCallOrder;
        const decoded = try contract.decode(entry.instruction);
        if (decoded.state_register != call.state_register or decoded.block_register != call.block_register) return error.ShaProgramMismatch;
        try call.validate();
        previous = call.execution_clock;
    }
}

const TapeView = struct {
    entries: []const native.Entry,
    pub fn len(self: TapeView) usize {
        return self.entries.len;
    }
    pub fn get(self: TapeView, index: usize) provider.Call {
        const call = &self.entries[index].call;
        return .{ .execution_clock = call.execution_clock, .state = call.state, .block = call.block };
    }
};

/// Exactly five final row arrays, independent of call count; no tape clone.
pub fn prepare(a: std.mem.Allocator, entries: []const native.Entry, total_steps: u32) !Rows {
    return prepareForRecipe(false, a, entries, total_steps);
}

pub fn prepareForRecipe(comptime local_zero: bool, a: std.mem.Allocator, entries: []const native.Entry, total_steps: u32) !RowsForRecipe(local_zero) {
    const Caller = if (local_zero) @import("sha256_caller_local_zero_v1.zig") else caller;
    const geometry = try Geometry.init(entries.len);
    try preflight(entries, total_steps);
    var compression = try provider.prepareView(a, TapeView{ .entries = entries });
    errdefer compression.deinit();
    const callers = try a.alloc(Caller.Row, @as(usize, 1) << @intCast(geometry.logs[4]));
    errdefer a.free(callers);
    @memset(callers, @splat(M.zero()));
    for (entries, callers[0..entries.len]) |entry, *row| row.* = try Caller.row(entry.call);
    return .{ .allocator = a, .geometry = geometry, .compression = compression, .callers = callers };
}

fn fixture(clock: u32) native.Entry {
    const sha = @import("sha256_compression.zig");
    const state = sha.initial_state;
    const block: [64]u8 = @splat(@truncate(clock));
    return .{ .instruction = contract.encode(3, 9), .call = .{
        .execution_clock = clock,
        .pc = 1024,
        .state_register = 3,
        .block_register = 9,
        .state_ptr = 4096,
        .block_ptr = 8192,
        .pointer_previous_clocks = .{ 1, 2 },
        .memory_previous_clocks = @splat(3),
        .state = state,
        .block = block,
        .output = sha.compress(state, block),
    } };
}

fn allocationCase(a: std.mem.Allocator) !void {
    const entries = [_]native.Entry{ fixture(3), fixture(7), fixture(9) };
    var rows = try prepare(a, &entries, 9);
    defer rows.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 9, 8, 8, 5, 4 }, &rows.geometry.logs);
    for (entries, 0..) |entry, i| try std.testing.expectEqual(entry.call.execution_clock, rows.callers[i][caller.Layout.clock].toU32());
    for (rows.callers[entries.len..]) |row| try std.testing.expectEqualSlices(M, &@as(caller.Row, @splat(M.zero())), &row);
}

test "SHA provider execution tape ownership and caller preflight" {
    try allocationCase(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
    var entry = fixture(3);
    try std.testing.expectError(error.InvalidShaCallOrder, preflight(&.{entry}, 2));
    try std.testing.expectError(error.InvalidShaCallOrder, preflight(&.{ entry, entry }, 3));
    entry.instruction = contract.encode(4, 9);
    try std.testing.expectError(error.ShaProgramMismatch, preflight(&.{entry}, 3));
    var empty = try prepare(std.testing.allocator, &.{}, 0);
    defer empty.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1, 4 }, &empty.geometry.logs);
    inline for (empty.tuple()) |rows| for (rows) |row| for (row) |value| try std.testing.expectEqual(M.zero(), value);
}

test "SHA provider zero-call segment satisfies every AIR and emits only valid padding lookups" {
    const lang = @import("../lang/mod.zig");
    const support = @import("../../recursion/air/test_support.zig");
    const tables = @import("../lookups/tables/schema.zig");
    inline for (Airs) |Air| {
        var definition = try Air.build(std.testing.allocator);
        defer definition.deinit();
        const row: Air.Row = @splat(M.zero());
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        for (definition.arena.constraintsView()) |constraint| try std.testing.expect(values[lang.types.idIndex(constraint.root)].isZero());
        for (definition.arena.effectsView(), 0..) |event, event_index| {
            if (values[lang.types.idIndex(event.liveness.?)].isZero()) continue;
            const ids = definition.arena.effectValues(@enumFromInt(event_index)).?;
            var tuple: [7]M = undefined;
            for (ids, 0..) |id, i| tuple[i] = values[lang.types.idIndex(id)];
            var matched = false;
            inline for (.{ tables.Kind.bitwise, tables.Kind.range_check_8_8, tables.Kind.range_check_8_8_4, tables.Kind.range_check_20 }) |kind| {
                const domain = @field(lang.relation.Domain, @tagName(kind));
                if (event.binding.?.schema == lang.relation.id(domain)) {
                    _ = try tables.indexBase(kind, tuple[0..ids.len]);
                    matched = true;
                }
            }
            try std.testing.expect(matched);
        }
    }
}
