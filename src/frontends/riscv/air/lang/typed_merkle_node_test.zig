const std = @import("std");
const typed = @import("typed_merkle_node.zig");
const native = @import("../memory_commitment/merkle_node.zig");
const admission = @import("../memory_commitment/merkle_typed_admission.zig");
const relations_mod = @import("../relation_challenges.zig");
const entries = @import("../lookups/entry.zig");
const Q = @import("stwo_core").fields.qm31.QM31;

test "typed Merkle definition preserves off-trace direct roots and ordered events" {
    var definition = try typed.Definition.init(std.testing.allocator);
    defer definition.deinit();
    var degree = try @import("degree.zig").analyze(std.testing.allocator, &definition.arena);
    defer degree.deinit();
    try std.testing.expectEqual(@as(u32, 3), degree.maximumConstraintDegree());
    try std.testing.expectEqual(@as(usize, 7), definition.arena.constraints.items.len);
    var draws: [relations_mod.DRAW_COUNT]Q = undefined;
    for (&draws, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(i + 1), 7, 11, 13);
    const relations = relations_mod.Relations.fromDrawSequence(&draws);
    for (0..8) |sample| {
        var main: [10]Q = undefined;
        for (&main, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(sample * 19 + i), @intCast(sample), 3, 5);
        const active = Q.fromU32Unchecked(@intCast(sample), 0, 0, 0);
        const expected = try definition.evaluate(Q, std.testing.allocator, main, active);
        const actual = native.evaluateGeneric(Q, main, active, Q.one(), .{Q.zero()} ** 3, .{Q.zero()} ** 3, .{Q.zero()} ** 3, &relations);
        try std.testing.expectEqualSlices(Q, &expected.direct, actual[3..]);
        const native_events = native.entriesGeneric(Q, main);
        try std.testing.expectEqual(expected.lookups.len, native_events.len);
        for (expected.lookups.entries[0..expected.lookups.len], native_events.entries[0..native_events.len]) |a, b| {
            try std.testing.expectEqual(a.domain, b.domain);
            try std.testing.expectEqual(a.arity, b.arity);
            try std.testing.expectEqualDeep(a.numerator, b.numerator);
            try std.testing.expectEqualSlices(Q, a.values[0..a.arity], b.values[0..b.arity]);
        }
    }
}
const Mutation = enum { direct, interaction, numerator, order, domain, external, geometry };
fn Changed(comptime mutation: Mutation) type {
    return struct {
        pub const N_MAIN_COLUMNS = 10;
        pub const N_SUMS = 3;
        pub const N_CONSTRAINTS = 10;
        pub const N_INTERACTION_COLUMNS = if (mutation == .geometry) 13 else 12;
        pub const N_EXTERNAL_PROVIDER_CONSTRAINTS = 13;
        pub fn evaluateGeneric(comptime S: type, main: [10]S, active: S, first: S, sums: [3]S, previous: [3]S, claims: [3]S, relations: anytype) [10]S {
            var result = native.evaluateGeneric(S, main, active, first, sums, previous, claims, relations);
            if (mutation == .direct) result[3] = result[3].add(S.one());
            if (mutation == .interaction) result[0] = result[0].add(S.one());
            return result;
        }
        pub fn evaluateExternalProviderCallerGeneric(comptime S: type, main: [10]S, active: S, first: S, sums: [3]S, previous: [3]S, claims: [3]S, relations: anytype) [13]S {
            var result = native.evaluateExternalProviderCallerGeneric(S, main, active, first, sums, previous, claims, relations);
            if (mutation == .external) result[10] = main[7];
            return result;
        }
        pub fn entriesGeneric(comptime S: type, main: [10]S) entries.Builder(S).List {
            var result = native.entriesGeneric(S, main);
            if (mutation == .numerator) result.entries[0].numerator = result.entries[0].numerator.neg();
            if (mutation == .order) std.mem.swap(entries.Builder(S).Entry, &result.entries[0], &result.entries[1]);
            if (mutation == .domain) result.entries[0].domain = .bitwise;
            return result;
        }
    };
}
test "typed Merkle admission checks interactions metadata order and external caller roots" {
    try admission.validate(std.testing.allocator);
    inline for (comptime std.meta.tags(Mutation)) |mutation| {
        try std.testing.expectError(if (mutation == .geometry) error.MerkleTypedGeometryMismatch else error.MerkleTypedSpecializationMismatch, admission.validateSpecialization(Changed(mutation), std.testing.allocator));
    }
}
test "typed Merkle definition unwinds allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 3 });
    try std.testing.expectError(error.OutOfMemory, typed.Definition.init(failing.allocator()));
}

test "typed Merkle admission returns allocation errors without partial acceptance" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, admission.validate, .{});
}
