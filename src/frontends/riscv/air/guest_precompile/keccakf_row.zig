//! One ordered Keccak row evaluation for native and recursive consumers.
//! Mask admission and trace access stay with each consumer. Interaction reads
//! remain lazy: recording scalars must emit direct, lookup, then LogUp work.

const direct = @import("keccakf_direct.zig");
const interaction = @import("keccakf_interaction_plan.zig");
const logup = @import("../logup.zig");

pub const direct_constraint_count = direct.constraint_count;
pub const interaction_constraint_count = interaction.batch_count;
pub const constraint_count = direct_constraint_count + interaction_constraint_count;

pub fn Row(comptime S: type) type {
    return struct {
        main: []const S,
        previous_io: []const S,
        state_minus_two: []const S,
        state_minus_one: []const S,
        state_plus_one: []const S,
        state_plus_two: []const S,
        state_plus_twenty_seven: []const S,
        selectors: []const S,
        second_active: S,
    };
}

pub fn Batch(comptime S: type) type {
    return struct { current: S, previous: S, claimed: S };
}

/// reader.begin() admits interaction access and returns is_first; reader.at()
/// loads one ordered batch. Both can fail without changing the sink protocol.
pub fn evaluateGeneric(comptime S: type, row: Row(S), relations: anytype, reader: anytype, sink: anytype) !void {
    try direct.evaluateGeneric(
        S,
        row.main,
        row.previous_io,
        row.state_minus_two,
        row.state_minus_one,
        row.state_plus_one,
        row.state_plus_two,
        row.selectors,
        row.second_active,
        sink,
    );
    const pairs = try interaction.rowPairsGeneric(
        S,
        row.main,
        row.state_plus_one,
        row.state_plus_twenty_seven,
        row.selectors,
        relations,
    );
    const is_first = try reader.begin();
    for (pairs, 0..) |pair, batch| {
        const values = try reader.at(batch);
        sink.add(logup.pairConstraintGeneric(
            @TypeOf(is_first),
            values.current,
            values.previous,
            is_first,
            values.claimed,
            pair,
        ), 3);
    }
}

test "Keccak shared row preserves scalar constraint values degrees and lazy errors" {
    try testScalarRow(@import("stwo_core").fields.m31.M31);
    try testScalarRow(@import("stwo_core").fields.qm31.QM31);
}

fn testScalarRow(comptime S: type) !void {
    const std = @import("std");
    const M31 = @import("stwo_core").fields.m31.M31;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const trace = @import("keccakf_trace.zig");
    const witness = @import("keccakf_witness.zig");
    const relations_mod = @import("keccakf_relations.zig");
    const Entry = struct { value: QM31, degree: u8 };
    const Sink = struct {
        entries: []Entry,
        count: usize = 0,

        pub fn add(self: *@This(), value: anytype, degree: u8) void {
            self.entries[self.count] = .{
                .value = if (@TypeOf(value) == M31) QM31.fromBase(value) else value,
                .degree = degree,
            };
            self.count += 1;
        }
    };
    const Reader = struct {
        begin_count: usize = 0,
        reads: usize = 0,
        fail: bool = false,

        pub fn begin(self: *@This()) !QM31 {
            self.begin_count += 1;
            if (self.fail) return error.InvalidClaimCount;
            return QM31.one();
        }

        pub fn at(self: *@This(), batch: usize) error{}!Batch(QM31) {
            std.debug.assert(batch == self.reads);
            self.reads += 1;
            return .{
                .current = QM31.fromBase(M31.fromCanonical(@intCast(batch + 7))),
                .previous = QM31.fromBase(M31.fromCanonical(@intCast(batch + 3))),
                .claimed = QM31.fromBase(M31.fromCanonical(@intCast(batch + 11))),
            };
        }
    };
    var main: [trace.Layout.main_columns]S = undefined;
    for (&main, 0..) |*value, index| {
        const base = M31.fromCanonical(@intCast(index % 19));
        value.* = if (S == M31) base else QM31.fromBase(base);
    }
    const states = [_]S{S.one()} ** witness.state_cell_count;
    const previous = [_]S{S.zero()} ** (2 * relations_mod.io_arity);
    const selectors = [_]S{S.one()} ** witness.row_count;
    const row = Row(S){
        .main = &main,
        .previous_io = &previous,
        .state_minus_two = &states,
        .state_minus_one = &states,
        .state_plus_one = &states,
        .state_plus_two = &states,
        .state_plus_twenty_seven = &states,
        .selectors = &selectors,
        .second_active = S.one(),
    };
    const relations = relations_mod.Relations.dummy();
    const expected_entries = try std.testing.allocator.alloc(Entry, constraint_count);
    defer std.testing.allocator.free(expected_entries);
    const actual_entries = try std.testing.allocator.alloc(Entry, constraint_count);
    defer std.testing.allocator.free(actual_entries);
    var expected = Sink{ .entries = expected_entries };
    // Retained pre-consolidation scalar reference, only in this regression.
    try direct.evaluateGeneric(S, row.main, row.previous_io, row.state_minus_two, row.state_minus_one, row.state_plus_one, row.state_plus_two, row.selectors, row.second_active, &expected);
    const pairs = try interaction.rowPairsGeneric(S, row.main, row.state_plus_one, row.state_plus_twenty_seven, row.selectors, &relations);
    var reference: Reader = .{};
    const is_first = try reference.begin();
    for (pairs, 0..) |pair, batch| {
        const values = try reference.at(batch);
        expected.add(logup.pairConstraint(values.current, values.previous, is_first, values.claimed, pair), 3);
    }
    var actual = Sink{ .entries = actual_entries };
    var reader: Reader = .{};
    try evaluateGeneric(S, row, &relations, &reader, &actual);
    try std.testing.expectEqual(constraint_count, expected.count);
    try std.testing.expectEqual(expected.count, actual.count);
    try std.testing.expectEqual(@as(usize, 1), reader.begin_count);
    try std.testing.expectEqual(interaction.batch_count, reader.reads);
    for (expected_entries, actual_entries) |wanted, found| {
        try std.testing.expect(wanted.value.eql(found.value));
        try std.testing.expectEqual(wanted.degree, found.degree);
    }

    var invalid_row = row;
    invalid_row.main = row.main[1..];
    reader = .{ .fail = true };
    actual.count = 0;
    try std.testing.expectError(error.InvalidTraceShape, evaluateGeneric(S, invalid_row, &relations, &reader, &actual));
    try std.testing.expectEqual(@as(usize, 0), reader.begin_count);
    try std.testing.expectEqual(@as(usize, 0), actual.count);
    try std.testing.expectError(error.InvalidClaimCount, evaluateGeneric(S, row, &relations, &reader, &actual));
    try std.testing.expectEqual(direct_constraint_count, actual.count);
    try std.testing.expectEqual(@as(usize, 0), reader.reads);
}
