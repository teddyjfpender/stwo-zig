//! Versioned native AIR envelope. The shipped instruction semantics remain
//! the authority for all source tuples; this recipe adds local constant-zero
//! evidence and applies one weight to each consume/emit/clock-gap triple.
//! No host zero test is used during polynomial evaluation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const trace = @import("../runner/trace.zig");
const canonical = @import("constraint_program.zig");
const entries = @import("lookups/opcode_entries.zig");
const entry = @import("stwo_riscv_air_lang").modules.shared_air_lookups_entry;
const zero = @import("x0_local_custody.zig");
pub const VERSION: u32 = 1;
pub const MAX_GROUPS: usize = 3;
pub const MAX_HINT_COLUMNS = MAX_GROUPS * zero.HINT_COLUMNS;
pub const MAX_MAIN_COLUMNS = trace.MAX_FAMILY_COLUMNS;
pub const MAX_CONSTRAINTS = canonical.Builder(Q).MAX_DIRECT_CONSTRAINTS + MAX_GROUPS * zero.CONSTRAINT_COUNT;

pub const Group = struct { consume: u8, emit: u8, gap: u8, ordinal: u8 };
pub const Schedule = struct {
    groups: [MAX_GROUPS]Group = undefined,
    len: u8 = 0,
    /// Only typed construction metadata selects effects. Dynamic tuple values
    /// (including a load/store address space) never change the schedule.
    pub fn fromList(list: anytype) !Schedule {
        var result = Schedule{};
        for (list.entries[0..list.len], 0..) |event, index| {
            if (event.domain == .memory_access and (event.access_ordinal == null or (event.role != .consume and event.role != .emit)))
                return error.UnboundX0AccessOrdinal;
            if (event.domain != .memory_access or event.role != .consume) continue;
            const ordinal = event.access_ordinal orelse return error.UnboundX0AccessOrdinal;
            if (ordinal != result.len + 1 or index + 2 >= list.len or result.len == MAX_GROUPS)
                return error.InvalidX0AccessSchedule;
            const emit = list.entries[index + 1];
            const gap = list.entries[index + 2];
            if (event.arity != 7 or emit.domain != .memory_access or emit.role != .emit or emit.arity != 7 or
                gap.domain != .range_check_20 or gap.role != .request or gap.arity != 1 or
                emit.access_ordinal != ordinal or gap.access_ordinal != ordinal)
                return error.InvalidX0AccessSchedule;
            result.groups[result.len] = .{ .consume = @intCast(index), .emit = @intCast(index + 1), .gap = @intCast(index + 2), .ordinal = ordinal };
            result.len += 1;
        }
        // Every ordinal-bearing effect belongs to exactly one authenticated
        // triple. An additional effect cannot silently survive the transform.
        var effects: usize = 0;
        for (list.entries[0..list.len]) |event| if (event.access_ordinal != null) {
            effects += 1;
        };
        if (effects != 3 * @as(usize, result.len)) return error.InvalidX0AccessSchedule;
        return result;
    }
};

pub fn schedule(family: trace.OpcodeFamily) !Schedule {
    const columns = [_]Q{Q.zero()} ** trace.MAX_FAMILY_COLUMNS;
    const list = try entries.fromMain(family, columns[0..trace.nColumnsForFamily(family)]);
    return Schedule.fromList(&list);
}
pub fn mainColumnCount(family: trace.OpcodeFamily) !usize {
    return trace.nColumnsForFamily(family) + @as(usize, (try schedule(family)).len) * zero.HINT_COLUMNS;
}
pub fn constraintCount(family: trace.OpcodeFamily) !usize {
    return canonical.Builder(Q).constraintCount(family) + @as(usize, (try schedule(family)).len) * zero.CONSTRAINT_COUNT;
}

pub fn Builder(comptime S: type) type {
    return struct {
        const Self = @This();
        const Base = canonical.Builder(S);
        const Events = entries.Entries(S);
        const Zero = zero.Algebra(S);
        pub const Direct = struct {
            values: [MAX_CONSTRAINTS]S = undefined,
            len: usize = 0,

            pub fn allZero(self: @This()) bool {
                for (self.values[0..self.len]) |value| {
                    if (!value.isZero()) return false;
                }
                return true;
            }
        };
        pub fn access(list: *const entry.Builder(S).List, group: Group, hints: []const S) !Zero.Access {
            if (hints.len != 2) return error.InvalidX0HintGeometry;
            const consume = list.entries[group.consume];
            const emit = list.entries[group.emit];
            return .{ .active = emit.numerator, .space = consume.values[0], .address = consume.values[1], .previous_clock = consume.values[2], .before = consume.values[3..7].*, .after = emit.values[3..7].*, .nonzero = hints[0], .inverse = hints[1] };
        }
        pub fn direct(family: trace.OpcodeFamily, columns: []const S, selector: S) !Direct {
            const old_width = trace.nColumnsForFamily(family);
            if (columns.len < old_width) return error.InvalidX0HintGeometry;
            const list = try Events.fromMain(family, columns[0..old_width]);
            const layout = try Schedule.fromList(&list);
            if (columns.len != old_width + @as(usize, layout.len) * 2) return error.InvalidX0HintGeometry;
            const original = (try Base.buildDirect(family, columns[0..old_width], selector)).direct_constraints;
            var result = Direct{ .len = original.len };
            @memcpy(result.values[0..original.len], original.values[0..original.len]);
            for (layout.groups[0..layout.len], 0..) |group, index| {
                const terms = Zero.constraints(try Self.access(&list, group, columns[old_width + 2 * index ..][0..2]));
                @memcpy(result.values[result.len..][0..terms.len], &terms);
                result.len += terms.len;
            }
            return result;
        }
        pub fn lookups(family: trace.OpcodeFamily, columns: []const S) !entry.Builder(S).List {
            const old_width = trace.nColumnsForFamily(family);
            if (columns.len < old_width) return error.InvalidX0HintGeometry;
            var list = try Events.fromMain(family, columns[0..old_width]);
            const layout = try Schedule.fromList(&list);
            if (columns.len != old_width + @as(usize, layout.len) * 2) return error.InvalidX0HintGeometry;
            for (layout.groups[0..layout.len], 0..) |group, index| {
                const keep = Zero.custodyWeight(try Self.access(&list, group, columns[old_width + 2 * index ..][0..2]));
                inline for (.{ "consume", "emit", "gap" }) |field| {
                    const event = &list.entries[@field(group, field)];
                    event.numerator = event.numerator.mul(keep);
                }
            }
            return list;
        }
    };
}

/// Host-only recipe. All guards still appear in the independently evaluated
/// direct AIR. Reads the exact old physical cells; no instruction replay.
pub fn fillHints(family: trace.OpcodeFamily, physical: []const M, hints: []M) !void {
    const old_width = trace.nColumnsForFamily(family);
    if (physical.len != old_width) return error.InvalidX0HintGeometry;
    var lifted: [trace.MAX_FAMILY_COLUMNS]Q = undefined;
    for (physical, lifted[0..old_width]) |value, *out| out.* = Q.fromBase(value);
    const list = try entries.fromMain(family, lifted[0..old_width]);
    const layout = try Schedule.fromList(&list);
    if (hints.len != @as(usize, layout.len) * 2) return error.InvalidX0HintGeometry;
    for (layout.groups[0..layout.len], 0..) |group, index| {
        const event = list.entries[group.emit];
        const active = try baseWitness(event.numerator);
        if (active != 0 and active != 1) return error.InvalidX0ActiveWitness;
        const hint = if (active == 0) zero.Hint{ .nonzero = M.zero(), .inverse = M.zero() } else try zero.Hint.forAddress(std.math.cast(u1, try baseWitness(event.values[0])) orelse return error.InvalidX0SpaceWitness, try baseWitness(event.values[1]));
        hints[2 * index] = hint.nonzero;
        hints[2 * index + 1] = hint.inverse;
    }
}
pub fn baseWitness(value: Q) !u32 {
    const parts = value.toM31Array();
    for (parts[1..]) |part| if (!part.isZero()) return error.InvalidX0BaseWitness;
    return parts[0].toU32();
}

test "block-v5 x0 native envelope retains authentic schedules domains roles and ordinals" {
    const old = [_]Q{Q.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var columns: [MAX_MAIN_COLUMNS]Q = @splat(Q.zero());
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        const original = try entries.fromMain(family, old[0..trace.nColumnsForFamily(family)]);
        const width = try mainColumnCount(family);
        const transformed = try Builder(Q).lookups(family, columns[0..width]);
        try std.testing.expectEqual(original.len, transformed.len);
        try std.testing.expectEqual(original.batch_size, transformed.batch_size);
        for (original.entries[0..original.len], transformed.entries[0..transformed.len]) |before, after| {
            try std.testing.expectEqual(before.domain, after.domain);
            try std.testing.expectEqual(before.role, after.role);
            try std.testing.expectEqual(before.access_ordinal, after.access_ordinal);
            try std.testing.expectEqual(before.arity, after.arity);
            for (before.values[0..before.arity], after.values[0..after.arity]) |first, last| try std.testing.expect(first.eql(last));
        }
        const direct = try Builder(Q).direct(family, columns[0..width], Q.zero());
        try std.testing.expectEqual(try constraintCount(family), direct.len);
    }
}
