const std = @import("std");
const production = @import("../memory_commitment/poseidon2_air.zig");
const compat = @import("typed_poseidon2_compat.zig");

test "Poseidon2 compatibility schedule pins every legacy range and round" {
    var schedule = try compat.generate(std.testing.allocator);
    defer schedule.deinit(std.testing.allocator);
    try schedule.validate();
    try std.testing.expectEqualStrings(
        "stark-v.poseidon2.compatibility",
        compat.POLICY_NAME,
    );
    try std.testing.expectEqual(
        @as(u32, 0x5032_4331),
        @intFromEnum(schedule.identity.policy),
    );

    try expectEntry(try compat.expected(0), 0, 17, 1, .external_round, 0, 0, .square);
    try expectEntry(try compat.expected(1), 1, 18, 2, .external_round, 0, 0, .fourth_power);
    try expectEntry(try compat.expected(31), 31, 48, 32, .external_round, 0, 15, .fourth_power);
    try expectEntry(try compat.expected(32), 32, 49, 33, .external_round, 1, 0, .shifted);
    try expectEntry(try compat.expected(175), 175, 192, 176, .external_round, 3, 15, .fourth_power);
    try expectEntry(try compat.expected(176), 176, 193, 177, .internal_round, 0, 0, .shifted);
    try expectEntry(try compat.expected(217), 217, 234, 218, .internal_round, 13, 0, .fourth_power);
    try expectEntry(try compat.expected(218), 218, 235, 219, .external_round, 4, 0, .shifted);
    try expectEntry(try compat.expected(409), 409, 426, 410, .external_round, 7, 15, .fourth_power);
    try expectEntry(try compat.expected(410), 410, 427, 411, .output, compat.NO_ROUND, 0, .output);
    try expectEntry(try compat.expected(425), 425, 442, 426, .output, compat.NO_ROUND, 15, .output);

    var phases = [_]usize{0} ** std.meta.fields(compat.Phase).len;
    var roles = [_]usize{0} ** std.meta.fields(compat.Role).len;
    var external_rounds = [_]usize{0} ** 8;
    var internal_rounds = [_]usize{0} ** 14;
    for (schedule.materializations) |entry| {
        phases[@intFromEnum(entry.phase)] += 1;
        roles[@intFromEnum(entry.role)] += 1;
        switch (entry.phase) {
            .external_round => external_rounds[entry.round] += 1,
            .internal_round => internal_rounds[entry.round] += 1,
            .output => {},
        }
    }
    try std.testing.expectEqualSlices(usize, &.{ 368, 42, 16 }, &phases);
    try std.testing.expectEqualSlices(usize, &.{ 126, 142, 142, 16 }, &roles);
    try std.testing.expectEqualSlices(usize, &.{ 32, 48, 48, 48, 48, 48, 48, 48 }, &external_rounds);
    try std.testing.expectEqualSlices(usize, &(.{3} ** 14), &internal_rounds);
}

test "Poseidon2 compatibility column map covers exactly 445 current columns" {
    try std.testing.expectEqual(@as(usize, production.N_MAIN_COLUMNS), compat.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 443), compat.WIDE_COLUMN);
    try std.testing.expectEqual(@as(usize, 444), compat.IO_COLUMN);

    for (0..compat.N_MAIN_COLUMNS) |index| {
        switch (try compat.column(index)) {
            .enabler => try std.testing.expectEqual(@as(usize, 0), index),
            .input => |lane| try std.testing.expectEqual(
                compat.INPUT_START + lane,
                index,
            ),
            .materialization => |entry| try std.testing.expectEqual(
                compat.TEMPORARY_START + entry.ordinal,
                index,
            ),
            .wide => try std.testing.expectEqual(compat.WIDE_COLUMN, index),
            .io => try std.testing.expectEqual(compat.IO_COLUMN, index),
        }
    }
    try std.testing.expectError(
        error.ColumnOutOfRange,
        compat.column(compat.N_MAIN_COLUMNS),
    );
}

test "Poseidon2 compatibility names separate physical placement from meaning" {
    var storage: [160]u8 = undefined;
    try expectColumnName(&storage, 0, "poseidon2.enabler");
    try expectColumnName(&storage, 16, "poseidon2.input[15]");
    try expectColumnName(&storage, 17, "poseidon2.temporary[0]");
    try expectColumnName(&storage, 442, "poseidon2.temporary[425]");
    try expectColumnName(&storage, 443, "poseidon2.wide");
    try expectColumnName(&storage, 444, "poseidon2.io");

    try expectSemanticPath(
        &storage,
        0,
        "riscv.poseidon2_m31.external_round[0].lane[0].square",
    );
    try expectSemanticPath(
        &storage,
        32,
        "riscv.poseidon2_m31.external_round[1].lane[0].shifted",
    );
    try expectSemanticPath(
        &storage,
        217,
        "riscv.poseidon2_m31.internal_round[13].lane[0].fourth_power",
    );
    try expectSemanticPath(
        &storage,
        409,
        "riscv.poseidon2_m31.external_round[7].lane[15].fourth_power",
    );
    try expectSemanticPath(
        &storage,
        425,
        "riscv.poseidon2_m31.output[15]",
    );
}

test "Poseidon2 compatibility schedule validation rejects every drift class" {
    var schedule = try compat.generate(std.testing.allocator);
    defer schedule.deinit(std.testing.allocator);

    var identity = schedule.identity;
    identity.format_version += 1;
    try std.testing.expectError(error.FormatVersionMismatch, identity.validate());
    identity = schedule.identity;
    identity.policy = @enumFromInt(0);
    try std.testing.expectError(error.PolicyMismatch, identity.validate());
    identity = schedule.identity;
    identity.policy_version += 1;
    try std.testing.expectError(error.PolicyVersionMismatch, identity.validate());
    identity = schedule.identity;
    identity.maximum_constraint_degree += 1;
    try std.testing.expectError(error.DegreeBudgetMismatch, identity.validate());
    identity = schedule.identity;
    identity.main_columns -= 1;
    try std.testing.expectError(error.GeometryMismatch, identity.validate());

    try std.testing.expectError(
        error.EntryCountMismatch,
        compat.validateMaterializations(schedule.materializations[0 .. compat.N_MATERIALIZATIONS - 1]),
    );
    const original = schedule.materializations[200];
    defer schedule.materializations[200] = original;
    inline for (.{
        .{ "ordinal", error.OrdinalMismatch },
        .{ "column", error.ColumnOutOfRange },
        .{ "constraint", error.ConstraintMismatch },
        .{ "phase", error.PhaseMismatch },
        .{ "round", error.RoundMismatch },
        .{ "lane", error.LaneMismatch },
        .{ "role", error.RoleMismatch },
    }) |case| {
        schedule.materializations[200] = original;
        if (comptime std.mem.eql(u8, case[0], "ordinal")) {
            schedule.materializations[200].ordinal += 1;
        } else if (comptime std.mem.eql(u8, case[0], "column")) {
            schedule.materializations[200].column += 1;
        } else if (comptime std.mem.eql(u8, case[0], "constraint")) {
            schedule.materializations[200].constraint += 1;
        } else if (comptime std.mem.eql(u8, case[0], "phase")) {
            schedule.materializations[200].phase = .output;
        } else if (comptime std.mem.eql(u8, case[0], "round")) {
            schedule.materializations[200].round += 1;
        } else if (comptime std.mem.eql(u8, case[0], "lane")) {
            schedule.materializations[200].lane += 1;
        } else {
            schedule.materializations[200].role = .output;
        }
        try std.testing.expectError(case[1], schedule.validate());
    }
}

test "Poseidon2 compatibility schedule renders byte-identically on clean replays" {
    var first = try compat.generate(std.testing.allocator);
    defer first.deinit(std.testing.allocator);
    var second = try compat.generate(std.testing.allocator);
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqualDeep(first.identity, second.identity);
    try std.testing.expectEqualSlices(
        compat.Materialization,
        first.materializations,
        second.materializations,
    );

    var first_bytes: std.ArrayList(u8) = .empty;
    defer first_bytes.deinit(std.testing.allocator);
    try compat.writeSchedule(first_bytes.writer(std.testing.allocator), first);
    var second_bytes: std.ArrayList(u8) = .empty;
    defer second_bytes.deinit(std.testing.allocator);
    try compat.writeSchedule(second_bytes.writer(std.testing.allocator), second);
    try std.testing.expectEqualSlices(u8, first_bytes.items, second_bytes.items);
    try std.testing.expect(std.mem.startsWith(
        u8,
        first_bytes.items,
        "# stwo-zig typed-air poseidon2-compatibility-schedule v1\n" ++
            "# policy stark-v.poseidon2.compatibility v1; materializer " ++
            "stwo.typed-air.materialize.degree-bounded-v1 v1; maximum-degree 3; " ++
            "width 16; materializations 426; main-columns 445\n",
    ));
    try std.testing.expect(std.mem.endsWith(
        u8,
        first_bytes.items,
        "425\t442\t426\toutput\t-\t15\toutput\triscv.poseidon2_m31.output[15]\n",
    ));
}

fn expectEntry(
    actual: compat.Materialization,
    ordinal: u16,
    column: u16,
    constraint: u16,
    phase: compat.Phase,
    round: u8,
    lane: u8,
    role: compat.Role,
) !void {
    try std.testing.expectEqualDeep(compat.Materialization{
        .ordinal = ordinal,
        .column = column,
        .constraint = constraint,
        .phase = phase,
        .round = round,
        .lane = lane,
        .role = role,
    }, actual);
}

fn expectColumnName(storage: []u8, index: usize, expected_name: []const u8) !void {
    var writer = std.Io.Writer.fixed(storage);
    try compat.writeColumnName(&writer, index);
    try std.testing.expectEqualStrings(expected_name, writer.buffered());
}

fn expectSemanticPath(storage: []u8, ordinal: usize, expected_path: []const u8) !void {
    var writer = std.Io.Writer.fixed(storage);
    try compat.writeSemanticPath(&writer, try compat.expected(ordinal));
    try std.testing.expectEqualStrings(expected_path, writer.buffered());
}
