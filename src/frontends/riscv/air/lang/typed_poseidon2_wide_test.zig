const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const typed = @import("typed_poseidon2_wide.zig");
const native = @import("../memory_commitment/poseidon2_wide_equations.zig");
const admission = @import("../memory_commitment/poseidon2_wide_typed_admission.zig");
const entries = @import("../lookups/entry.zig");

test "typed wide Poseidon binds all direct equations on arbitrary extension rows" {
    var definition = try typed.Definition.init(std.testing.allocator);
    defer definition.deinit();
    var degrees = try @import("degree.zig").analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 3), degrees.maximumConstraintDegree());
    try std.testing.expectEqual(@as(usize, 430), definition.arena.constraints.items.len);
    var prng = std.Random.DefaultPrng.init(0x7769646554797065);
    const random = prng.random();
    for (0..12) |sample| {
        var main: [typed.MAIN_COLUMNS]Q = undefined;
        for (&main) |*v| v.* = Q.fromU32Unchecked(random.int(u30), random.int(u30), random.int(u30), random.int(u30));
        // Include inactive rows and invalid mode combinations, not only honest traces.
        if (sample < 8) {
            main[0] = Q.fromU32Unchecked(@intCast(sample & 1), 0, 0, 0);
            main[native.WIDE_COLUMN] = Q.fromU32Unchecked(@intCast((sample >> 1) & 1), 0, 0, 0);
            main[native.IO_COLUMN] = Q.fromU32Unchecked(@intCast((sample >> 2) & 1), 0, 0, 0);
        }
        const expected = try definition.evaluate(Q, std.testing.allocator, main);
        const actual = native.evaluateGeneric(Q, main);
        try std.testing.expectEqualSlices(Q, &actual, &expected.direct);
        const actual_events = native.entriesGeneric(Q, main);
        try std.testing.expectEqual(actual_events.len, expected.lookups.len);
        for (actual_events.entries[0..actual_events.len], expected.lookups.entries[0..expected.lookups.len]) |a, b| {
            try std.testing.expectEqual(a.domain, b.domain);
            try std.testing.expectEqual(a.role, b.role);
            try std.testing.expectEqual(a.access_ordinal, b.access_ordinal);
            try std.testing.expectEqual(a.arity, b.arity);
            try std.testing.expectEqualDeep(a.numerator, b.numerator);
            try std.testing.expectEqualSlices(Q, a.values[0..a.arity], b.values[0..b.arity]);
        }
    }
}
const Mutation = enum { enabler, first_round, full_round, internal_round, output, wide_flag, io_flag, exclusivity, interaction, numerator, tuple, order, role, geometry };
fn Changed(comptime mutation: Mutation) type {
    return struct {
        pub const N_MAIN_COLUMNS = native.N_MAIN_COLUMNS;
        pub const N_CONSTRAINTS = native.N_CONSTRAINTS;
        pub const N_SUMS = native.N_SUMS;
        pub const N_INTERACTION_COLUMNS = native.N_INTERACTION_COLUMNS + @intFromBool(mutation == .geometry);
        pub const MAXIMUM_CONSTRAINT_DEGREE = native.MAXIMUM_CONSTRAINT_DEGREE;
        pub fn evaluateGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) [N_CONSTRAINTS]S {
            var result = native.evaluateGeneric(S, main);
            const root: ?usize = switch (mutation) {
                .enabler => 0,
                .first_round => 1,
                .full_round => 33,
                .internal_round => 177,
                .output => 411,
                .wide_flag => 427,
                .io_flag => 428,
                .exclusivity => 429,
                else => null,
            };
            if (root) |index| result[index] = result[index].add(S.one());
            return result;
        }
        pub fn interactionConstraintsGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S, first: S, sums: [N_SUMS]S, previous: [N_SUMS]S, claims: [N_SUMS]S, challenges: anytype) [N_SUMS]S {
            var result = native.interactionConstraintsGeneric(S, main, first, sums, previous, claims, challenges);
            if (mutation == .interaction) result[1] = result[1].add(S.one());
            return result;
        }
        pub fn entriesGeneric(comptime S: type, main: [N_MAIN_COLUMNS]S) entries.Builder(S).List {
            var result = native.entriesGeneric(S, main);
            if (mutation == .numerator) result.entries[0].numerator = result.entries[0].numerator.neg();
            if (mutation == .tuple) result.entries[3].values[31] = result.entries[3].values[31].add(S.one());
            if (mutation == .order) std.mem.swap(entries.Builder(S).Entry, &result.entries[1], &result.entries[2]);
            if (mutation == .role) result.entries[0].role = .emit;
            return result;
        }
    };
}
test "wide Poseidon admission rejects equation interaction event and geometry drift" {
    try admission.validate(std.testing.allocator);
    inline for (comptime std.meta.tags(Mutation)) |mutation|
        try std.testing.expectError(if (mutation == .geometry) error.WidePoseidonTypedGeometryMismatch else error.WidePoseidonTypedSpecializationMismatch, admission.validateSpecialization(Changed(mutation), std.testing.allocator));
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    try admission.validate(allocator);
}
test "wide Poseidon admission propagates allocation failure without partial authority" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

test "canonical infrastructure admission covers the complete registry and repeated shards" {
    const Kind = @import("../statement.zig").InfraKind;
    const kinds = comptime std.meta.tags(Kind);
    const Descriptor = struct { kind: Kind };
    var statement: struct { n_infra: usize, infra_descs: [kinds.len + 1]Descriptor } = undefined;
    statement.n_infra = statement.infra_descs.len;
    for (kinds, statement.infra_descs[0..kinds.len]) |kind, *descriptor| descriptor.* = .{ .kind = kind };
    statement.infra_descs[kinds.len] = .{ .kind = .memory };
    try @import("../native_infrastructure_typed_admission.zig").validateStatement(&statement, std.testing.allocator);
}
