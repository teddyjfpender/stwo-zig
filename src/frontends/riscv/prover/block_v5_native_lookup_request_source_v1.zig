//! Exact table, state and auxiliary-clock projections of native columns.
//! Relation expressions and degree bounds come from the shipped typed AIR.
const std = @import("std");
const core = @import("stwo_core");
const opcode = @import("../runner/trace.zig");
const entries = @import("../air/lookups/opcode_entries.zig");
const interaction = @import("../air/lookups/opcode_interaction.zig");
const clock = @import("../air/clock_update_interaction.zig");
const tables = @import("../air/lookups/tables/mod.zig");
const shape_mod = @import("../air/statement.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const Q = core.fields.qm31.QM31;
pub const Kind = tables.schema.Kind;
pub const Partition = enum(u8) {
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
    registers_state,
    clock_memory_access,
    register_memory_access,
    register_clock_memory_access,
};
pub const PARTITION_COUNT = tables.schema.KIND_COUNT + 4;
fn partitionFor(domain: @import("../air/lookups/entry.zig").Domain) ?Partition {
    if (domain == .registers_state) return .registers_state;
    const kind = tables.counter.kindForDomain(domain) orelse return null;
    return @enumFromInt(@intFromEnum(kind));
}
fn arity(partition: Partition) usize {
    return switch (partition) {
        .registers_state => 2,
        .clock_memory_access, .register_memory_access, .register_clock_memory_access => 7,
        else => tables.schema.arity(@enumFromInt(@intFromEnum(partition))),
    };
}
fn relationDomain(domain: @import("../air/lookups/entry.zig").Domain) !@import("../air/lang/relation.zig").Domain {
    return switch (domain) {
        .registers_state => .registers_state,
        .memory_access => .memory_access,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        else => error.InvalidV5LookupRequestSlot,
    };
}
pub const Source = union(enum) { opcode: opcode.OpcodeFamily, clock };
pub const Slot = struct {
    source: Source,
    partition: Partition,
    entries: [2]u8,
    entry_count: u8,
    degree: u8,
    log_size: u32,
    n_rows: u32,
    main_offset: usize,
    width: usize,
    register_custody_mode: u32 = 0,
};
pub const Pair = struct {
    numerators: [2]Q = .{ Q.zero(), Q.zero() },
    denominators: [2]Q = .{ Q.one(), Q.one() },
    entry_count: u8,
    pub fn numerator(self: Pair) Q {
        return self.numerators[0].mul(self.denominators[1]).add(self.numerators[1].mul(self.denominators[0]));
    }
    pub fn denominator(self: Pair) Q {
        return self.denominators[0].mul(self.denominators[1]);
    }
};

pub fn fromCommittedMain(slot: Slot, main: []const Q, relations: *const universal.UniversalRelations) !Pair {
    const pair = try @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).lookupProjection(slot, main, relations);
    return .{ .entry_count = pair.entry_count, .numerators = pair.numerators, .denominators = pair.denominators };
}

/// One canonical order: component, table, declaration-order table entries.
/// Pairs never mix tables, so fresh claims retain their six-way partition.
pub fn slotsFromShape(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, external_retirements: u32) ![]Slot {
    return slotsFromShapeForMode(a, shape, external_retirements, 0);
}
pub fn slotsFromShapeForMode(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, external_retirements: u32, mode: u32) ![]Slot {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    try shape.validateBlake3ExecutionWithExternal(external_retirements);
    var out: std.ArrayList(Slot) = .empty;
    errdefer out.deinit(a);
    var offset: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| {
        var plan = try interaction.Plan.initForRecipe(a, desc.family, shape.localZeroCustody());
        defer plan.deinit();
        const degrees = try nodeDegrees(a, plan);
        defer a.free(degrees);
        if (mode == 1) for (plan.program.entries, 0..) |entry, index| {
            if (plan.domains[index] != .memory_access) continue;
            const space = plan.program.nodes[entry.values[0]];
            if ((space.op == .constant and space.value > 1) or
                (space.op != .constant and desc.family != .load_store)) return error.UnknownV5NativeRegisterSpace;
        };
        const n_partitions = if (mode == 0) @as(usize, 7) else @intFromEnum(Partition.register_memory_access) + 1;
        for (0..n_partitions) |kind_index| {
            const kind: Partition = @enumFromInt(kind_index);
            var selected: [@import("../air/lookups/entry.zig").MAX_ENTRIES]u8 = undefined;
            var count: usize = 0;
            for (plan.program.entries, 0..) |entry, index| if (partitionFor(plan.domains[index]) == kind or
                (kind == .register_memory_access and plan.domains[index] == .memory_access and
                    (plan.program.nodes[entry.values[0]].op != .constant or plan.program.nodes[entry.values[0]].value == 0)))
            {
                selected[count] = @intCast(index);
                count += 1;
            };
            var at: usize = 0;
            while (at < count) : (at += 2) {
                const size = @min(@as(usize, 2), count - at);
                const indexes: [2]u8 = .{ selected[at], if (size == 2) selected[at + 1] else 0 };
                var degree: u32 = 1;
                var denominator_degrees: [2]u32 = @splat(0);
                var numerator_degrees: [2]u32 = @splat(0);
                for (indexes[0..size], 0..) |index, i| {
                    const entry = plan.program.entries[index];
                    numerator_degrees[i] = degrees[entry.numerator];
                    if (kind == .register_memory_access) numerator_degrees[i] = try std.math.add(u32, numerator_degrees[i], degrees[entry.values[0]]);
                    for (entry.values[0..entry.arity]) |value| denominator_degrees[i] = @max(denominator_degrees[i], degrees[value]);
                }
                degree += denominator_degrees[0] + denominator_degrees[1];
                degree = @max(degree, @max(numerator_degrees[0] + denominator_degrees[1], numerator_degrees[1] + denominator_degrees[0]));
                if (degree > 255) return error.V5LookupRequestDegreeOverflow;
                try out.append(a, .{ .source = .{ .opcode = desc.family }, .partition = kind, .entries = indexes, .entry_count = @intCast(size), .degree = @intCast(degree), .log_size = desc.log_size, .n_rows = desc.n_rows, .main_offset = offset, .width = desc.n_columns, .register_custody_mode = mode });
            }
        }
        offset += desc.n_columns;
    }
    for (shape.infra_descs[0..shape.n_infra]) |desc| {
        if (desc.kind != .clock_update) return error.UnexpectedV5LookupProviderInNativeRoot;
        if (desc.n_columns != clock.N_MAIN_COLUMNS) return error.InvalidV5LookupRequestSlot;
        try out.append(a, .{ .source = .clock, .partition = .clock_memory_access, .entries = .{ 0, 1 }, .entry_count = 2, .degree = if (mode == 0) 3 else 4, .log_size = desc.log_size, .n_rows = desc.n_rows, .main_offset = offset, .width = desc.n_columns, .register_custody_mode = mode });
        if (mode == 1) try out.append(a, .{ .source = .clock, .partition = .register_clock_memory_access, .entries = .{ 0, 1 }, .entry_count = 2, .degree = 4, .log_size = desc.log_size, .n_rows = desc.n_rows, .main_offset = offset, .width = desc.n_columns, .register_custody_mode = mode });
        inline for (.{ .{ Partition.range_check_20, @as(u8, 2) }, .{ Partition.range_check_8_8, @as(u8, 3) } }) |item|
            try out.append(a, .{ .source = .clock, .partition = item[0], .entries = .{ item[1], 0 }, .entry_count = 1, .degree = 2, .log_size = desc.log_size, .n_rows = desc.n_rows, .main_offset = offset, .width = desc.n_columns, .register_custody_mode = mode });
        offset += desc.n_columns;
    }
    return out.toOwnedSlice(a);
}

fn nodeDegrees(a: std.mem.Allocator, plan: interaction.Plan) ![]u32 {
    const degrees = try a.alloc(u32, plan.program.nodes.len);
    errdefer a.free(degrees);
    for (plan.program.nodes, degrees) |node, *degree| degree.* = switch (node.op) {
        .constant => 0,
        .column => 1,
        .add, .sub => @max(degrees[node.lhs], degrees[node.rhs]),
        .mul => try std.math.add(u32, degrees[node.lhs], degrees[node.rhs]),
        .neg => degrees[node.lhs],
    };
    return degrees;
}
