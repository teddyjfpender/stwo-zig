const std = @import("std");
const typed = @import("typed_native_boundary.zig");
const admission = @import("../native_boundary_typed_admission.zig");
const entries = @import("../lookups/entry.zig");
const relations = @import("../relation_challenges.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
const Kind = typed.Kind;

test "typed boundary providers match arbitrary rows and exact ordered events" {
    var draws: [relations.DRAW_COUNT]Q = undefined;
    for (&draws, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(i + 1), 7, 13, 19);
    const challenges = relations.Relations.fromDrawSequence(&draws);
    inline for (comptime std.meta.tags(Kind)) |kind| {
        const D = typed.Definition(kind);
        var definition = try D.init(std.testing.allocator);
        defer definition.deinit();
        var degree = try @import("degree.zig").analyze(std.testing.allocator, &definition.arena);
        defer degree.deinit();
        try std.testing.expectEqual(@as(u32, if (typed.isTable(kind)) 0 else if (kind == .memory or kind == .memory_full) 3 else 2), degree.maximumConstraintDegree());
        try std.testing.expectEqual(@as(usize, D.DIRECT_CONSTRAINTS), definition.arena.constraints.items.len);
        for (0..8) |sample| {
            var main: [D.MAIN_COLUMNS]Q = undefined;
            var fixed: [D.FIXED_COLUMNS]Q = undefined;
            for (&main, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(sample * 17 + i), @intCast(sample), 3, 5);
            for (&fixed, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(sample + i), 11, 17, 23);
            const active = Q.fromU32Unchecked(@intCast(sample), 0, 0, 0);
            const expected = try definition.evaluate(Q, std.testing.allocator, main, active, fixed);
            const actual = try admission.Adapter(kind).evaluate(Q, main, active, fixed, Q.one(), .{Q.zero()} ** D.SUMS, .{Q.zero()} ** D.SUMS, .{Q.zero()} ** D.SUMS, &challenges);
            try std.testing.expectEqualSlices(Q, &expected.direct, actual[D.SUMS..]);
            const events = try admission.Adapter(kind).lookups(Q, main, active, fixed);
            try std.testing.expectEqual(expected.lookups.len, events.len);
            for (expected.lookups.entries[0..expected.lookups.len], events.entries[0..events.len]) |a, b| {
                try std.testing.expectEqual(a.domain, b.domain);
                try std.testing.expectEqual(a.arity, b.arity);
                try std.testing.expectEqualDeep(a.numerator, b.numerator);
                try std.testing.expectEqualSlices(Q, a.values[0..a.arity], b.values[0..b.arity]);
            }
        }
    }
}
const Mutation = enum { direct, interaction, numerator, order, role, geometry, fixed, inactive, tuple, table_geometry };
fn Changed(comptime kind: Kind, comptime mutation: Mutation) type {
    return struct {
        const D = typed.Definition(kind);
        const Base = admission.Adapter(kind);
        pub const MAIN_COLUMNS = Base.MAIN_COLUMNS;
        pub const FIXED_COLUMNS = Base.FIXED_COLUMNS;
        pub const SUMS = Base.SUMS;
        pub const TABLE_LOG_SIZE = Base.TABLE_LOG_SIZE + @intFromBool(mutation == .table_geometry);
        pub const CONSTRAINTS = Base.CONSTRAINTS;
        pub const INTERACTION_COLUMNS = Base.INTERACTION_COLUMNS + @intFromBool(mutation == .geometry);
        pub fn evaluate(comptime S: type, main: [D.MAIN_COLUMNS]S, active: S, fixed: [D.FIXED_COLUMNS]S, first: S, sums: [D.SUMS]S, previous: [D.SUMS]S, claims: [D.SUMS]S, challenges: anytype) ![CONSTRAINTS]S {
            var result = try Base.evaluate(S, main, active, fixed, first, sums, previous, claims, challenges);
            if (mutation == .direct) result[D.SUMS] = result[D.SUMS].add(S.one());
            if (mutation == .interaction) result[0] = result[0].add(S.one());
            if (mutation == .fixed) result[D.SUMS + 3] = active.mul(main[1].sub(fixed[1]));
            if (mutation == .inactive) result[3] = S.zero();
            return result;
        }
        pub fn lookups(comptime S: type, main: [D.MAIN_COLUMNS]S, active: S, fixed: [D.FIXED_COLUMNS]S) !entries.Builder(S).List {
            var result = try Base.lookups(S, main, active, fixed);
            if (mutation == .numerator) result.entries[0].numerator = result.entries[0].numerator.neg();
            if (mutation == .order) std.mem.swap(entries.Builder(S).Entry, &result.entries[0], &result.entries[1]);
            if (mutation == .role) result.entries[0].role = .emit;
            if (mutation == .tuple) result.entries[0].values[0] = result.entries[0].values[0].add(S.one());
            return result;
        }
    };
}
test "typed boundary admission rejects direct interaction ordering and geometry drift" {
    inline for (comptime std.meta.tags(Kind)) |kind| {
        try admission.validate(kind, std.testing.allocator);
        if (comptime typed.isTable(kind)) try std.testing.expectError(error.NativeBoundaryTypedGeometryMismatch, admission.validateSpecialization(kind, Changed(kind, .table_geometry), std.testing.allocator));
        inline for (.{ Mutation.direct, Mutation.interaction, Mutation.numerator, Mutation.order, Mutation.role, Mutation.geometry, Mutation.tuple }) |mutation| {
            if (comptime typed.isTable(kind) and (mutation == .direct or mutation == .order)) continue;
            try std.testing.expectError(if (mutation == .geometry) error.NativeBoundaryTypedGeometryMismatch else error.NativeBoundaryTypedSpecializationMismatch, admission.validateSpecialization(kind, Changed(kind, mutation), std.testing.allocator));
        }
    }
    inline for (.{ Mutation.fixed, Mutation.inactive }) |mutation|
        try std.testing.expectError(error.NativeBoundaryTypedSpecializationMismatch, admission.validateSpecialization(.program_fixed, Changed(.program_fixed, mutation), std.testing.allocator));
}
fn allocationCase(comptime kind: Kind) type {
    return struct {
        fn run(allocator: std.mem.Allocator) !void {
            try admission.validate(kind, allocator);
        }
    };
}
test "typed boundary admission propagates every allocation failure" {
    inline for (comptime std.meta.tags(Kind)) |kind|
        try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase(kind).run, .{});
}
test "typed full-state memory preserves zero multiplicity distinction" {
    var ordinary = try typed.Definition(.memory).init(std.testing.allocator);
    defer ordinary.deinit();
    var full = try typed.Definition(.memory_full).init(std.testing.allocator);
    defer full.deinit();
    const main = [_]Q{Q.zero()} ** 8;
    const a = try ordinary.evaluate(Q, std.testing.allocator, main, Q.one(), .{});
    const b = try full.evaluate(Q, std.testing.allocator, main, Q.one(), .{});
    try std.testing.expect(!a.direct[1].isZero());
    try std.testing.expect(b.direct[1].isZero());
    try std.testing.expectEqualDeep(a.lookups.entries[3].numerator, b.lookups.entries[3].numerator);
}
