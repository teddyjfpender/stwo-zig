const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const candidate = @import("typed_register_read_alias_candidate_v1.zig");
const base_authority = @import("typed_base_alu_imm_authority.zig");
const base_support = @import("typed_base_alu_imm_witness_test_support.zig");
const base_witness = @import("typed_base_alu_imm_witness.zig");
const eq_authority = @import("typed_branch_eq_authority.zig");
const eq_support = @import("typed_branch_eq_witness_test_support.zig");
const eq_witness = @import("typed_branch_eq_witness.zig");
const lt_authority = @import("typed_branch_lt_authority.zig");
const lt_support = @import("typed_branch_lt_witness_test_support.zig");
const lt_witness = @import("typed_branch_lt_witness.zig");
const Opcode = @import("../../runner/decode.zig").Opcode;

test "register-read alias profiles bind distinct fixed family programs" {
    const base = candidate.profile(.base_alu_imm);
    const eq = candidate.profile(.branch_eq);
    const lt = candidate.profile(.branch_lt);
    try base.validate();
    try eq.validate();
    try lt.validate();
    try std.testing.expect(!candidate.production_active);
    try std.testing.expectEqual(@as(u8, 31), base.main_column_count);
    try std.testing.expectEqual(@as(u8, 18), base.direct_constraint_count);
    try std.testing.expectEqual(@as(u8, 22), eq.main_column_count);
    try std.testing.expectEqual(@as(u8, 10), eq.direct_constraint_count);
    try std.testing.expectEqual(@as(u8, 29), lt.main_column_count);
    try std.testing.expectEqual(@as(u8, 25), lt.direct_constraint_count);
    try std.testing.expect(!std.mem.eql(
        u8,
        &base.verifier_program_identity,
        &eq.verifier_program_identity,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &eq.verifier_program_identity,
        &lt.verifier_program_identity,
    ));

    var malformed = base;
    malformed.aliases[0].source_column +%= 1;
    try std.testing.expectError(
        error.InvalidRegisterReadAliasProfile,
        malformed.validate(),
    );
    malformed = eq;
    malformed.removed_direct_roots[0] +%= 1;
    try std.testing.expectError(
        error.InvalidRegisterReadAliasProfile,
        malformed.validate(),
    );
    malformed = lt;
    malformed.verifier_program_identity[31] ^= 1;
    try std.testing.expectError(
        error.InvalidRegisterReadAliasProfile,
        malformed.validate(),
    );
}

test "BASE_ALU_IMM read alias preserves all four opcode roots and relations" {
    const opcodes = [_]Opcode{ .ADDI, .XORI, .ORI, .ANDI };
    const immediates = [_]i32{ -17, -1, 1023, 2047 };
    for (opcodes, immediates, 0..) |opcode, immediate, index| {
        const row = base_support.makeRow(
            opcode,
            5,
            6,
            0x80ff_7e01 +% @as(u32, @intCast(index)),
            immediate,
            @intCast(20 + index),
            @intCast(0x1000 + 4 * index),
            0x1122_3344,
            1,
            2,
        );
        const canonical_m31 = baseCanonical(row);
        const compact_m31 = try candidate.project(.base_alu_imm, canonical_m31);
        const canonical = toQM31(canonical_m31);
        const compact = toQM31(compact_m31);
        const expanded = candidate.expand(.base_alu_imm, QM31, compact);
        try expectScalarSlicesEqual(&canonical, &expanded);

        const program = try base_authority.Authority.pinned().buildProgram(
            QM31,
            &canonical,
            QM31.one(),
        );
        const direct = try candidate.baseAluImmDirect(QM31, compact, QM31.one());
        const expected = candidate.filterCanonicalDirect(
            .base_alu_imm,
            QM31,
            program.direct_constraints.values,
        );
        try expectScalarSlicesEqual(&expected, &direct);
        for (direct) |root| try std.testing.expect(root.isZero());
        try expectLookupsEqual(
            program.lookup_entries,
            try candidate.baseAluImmLookups(QM31, compact),
        );
    }

    var forged = baseCanonical(base_support.makeRow(
        .ADDI,
        5,
        6,
        7,
        1,
        20,
        0x1000,
        0,
        1,
        2,
    ));
    forged[18] = forged[18].add(M31.one());
    try std.testing.expectError(
        error.RegisterReadAliasMismatch,
        candidate.project(.base_alu_imm, forged),
    );
}

test "branch read aliases preserve all six branch opcode roots and relations" {
    const eq_cases = [_]struct {
        opcode: Opcode,
        lhs: u32,
        rhs: u32,
        immediate: i32,
    }{
        .{ .opcode = .BEQ, .lhs = 0x1234, .rhs = 0x1234, .immediate = 8 },
        .{ .opcode = .BNE, .lhs = 0x1234, .rhs = 0x5678, .immediate = -4 },
    };
    for (eq_cases, 0..) |case, index| {
        const row = eq_support.makeRow(
            case.opcode,
            2,
            3,
            case.lhs,
            case.rhs,
            case.immediate,
            @intCast(30 + index),
            0x2000,
            1,
            2,
        );
        const canonical_m31 = eqCanonical(row);
        const compact_m31 = try candidate.project(.branch_eq, canonical_m31);
        const canonical = toQM31(canonical_m31);
        const compact = toQM31(compact_m31);
        const expanded = candidate.expand(.branch_eq, QM31, compact);
        try expectScalarSlicesEqual(&canonical, &expanded);
        const program = try eq_authority.Authority.pinned().buildProgram(
            QM31,
            &canonical,
            QM31.one(),
        );
        const direct = try candidate.branchEqDirect(QM31, compact, QM31.one());
        const expected = candidate.filterCanonicalDirect(
            .branch_eq,
            QM31,
            program.direct_constraints.values,
        );
        try expectScalarSlicesEqual(&expected, &direct);
        for (direct) |root| try std.testing.expect(root.isZero());
        try expectLookupsEqual(
            program.lookup_entries,
            try candidate.branchEqLookups(QM31, compact),
        );
    }

    const lt_cases = [_]struct { opcode: Opcode, lhs: u32, rhs: u32 }{
        .{ .opcode = .BLT, .lhs = 0xffff_ffff, .rhs = 0 },
        .{ .opcode = .BLTU, .lhs = 0xffff_ffff, .rhs = 0 },
        .{ .opcode = .BGE, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff },
        .{ .opcode = .BGEU, .lhs = 9, .rhs = 9 },
    };
    for (lt_cases, 0..) |case, index| {
        const row = lt_support.makeRow(
            case.opcode,
            4,
            5,
            case.lhs,
            case.rhs,
            8,
            @intCast(40 + index),
            0x3000,
            1,
            2,
        );
        const canonical_m31 = ltCanonical(row);
        const compact_m31 = try candidate.project(.branch_lt, canonical_m31);
        const canonical = toQM31(canonical_m31);
        const compact = toQM31(compact_m31);
        const expanded = candidate.expand(.branch_lt, QM31, compact);
        try expectScalarSlicesEqual(&canonical, &expanded);
        const program = try lt_authority.Authority.pinned().buildProgram(
            QM31,
            &canonical,
            canonical[1],
            canonical[32],
            QM31.one(),
        );
        const direct = try candidate.branchLtDirect(
            QM31,
            compact,
            canonical[1],
            canonical[32],
            QM31.one(),
        );
        const expected = candidate.filterCanonicalDirect(
            .branch_lt,
            QM31,
            program.direct_constraints.values,
        );
        try expectScalarSlicesEqual(&expected, &direct);
        for (direct) |root| try std.testing.expect(root.isZero());
        try expectLookupsEqual(
            program.lookup_entries,
            try candidate.branchLtLookups(QM31, compact),
        );
    }

    var forged = eqCanonical(eq_support.makeRow(
        .BEQ,
        2,
        3,
        7,
        7,
        8,
        30,
        0x2000,
        1,
        2,
    ));
    forged[21] = forged[21].add(M31.one());
    try std.testing.expectError(
        error.RegisterReadAliasMismatch,
        candidate.project(.branch_eq, forged),
    );
}

test "register-read aliases project exact retained padded corpus savings" {
    const projection = try candidate.projectRetainedCost(.{
        .base_alu_imm = 252_953_632,
        .branch_eq = 114_752_144,
        .branch_lt = 117_317_888,
    });
    try std.testing.expectEqual(
        @as(u64, 1_011_814_528),
        projection.base_alu_imm_saved_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 918_017_152),
        projection.branch_eq_saved_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 938_543_104),
        projection.branch_lt_saved_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 2_868_374_784),
        projection.saved_main_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 11_473_499_136),
        projection.saved_raw_bytes,
    );
}

fn baseCanonical(row: base_witness.TraceRow) [base_witness.MAIN_COLUMN_COUNT]M31 {
    var storage: [base_witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var views: [base_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*owned, *view| view.* = owned;
    base_witness.writeActiveRow(&views, 0, row);
    var result: [base_witness.MAIN_COLUMN_COUNT]M31 = undefined;
    for (&result, storage) |*value, cell| value.* = cell[0];
    return result;
}

fn eqCanonical(row: eq_witness.TraceRow) [eq_witness.MAIN_COLUMN_COUNT]M31 {
    var storage: [eq_witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var views: [eq_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*owned, *view| view.* = owned;
    eq_witness.writeActiveRow(&views, 0, row);
    var result: [eq_witness.MAIN_COLUMN_COUNT]M31 = undefined;
    for (&result, storage) |*value, cell| value.* = cell[0];
    return result;
}

fn ltCanonical(row: lt_witness.TraceRow) [lt_witness.MAIN_COLUMN_COUNT]M31 {
    var storage: [lt_witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var views: [lt_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*owned, *view| view.* = owned;
    lt_witness.writeActiveRow(&views, 0, row);
    var result: [lt_witness.MAIN_COLUMN_COUNT]M31 = undefined;
    for (&result, storage) |*value, cell| value.* = cell[0];
    return result;
}

fn toQM31(values: anytype) [values.len]QM31 {
    var result: [values.len]QM31 = undefined;
    for (&result, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return result;
}

fn expectScalarSlicesEqual(expected: []const QM31, actual: []const QM31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try std.testing.expect(want.eql(got));
}

fn expectLookupsEqual(
    expected: entry.Builder(QM31).List,
    actual: entry.Builder(QM31).List,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected.batch_size, actual.batch_size);
    for (expected.entries[0..expected.len], actual.entries[0..actual.len]) |
        want,
        got,
    | {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        try std.testing.expect(want.numerator.eql(got.numerator));
        for (want.values[0..want.arity], got.values[0..got.arity]) |
            want_value,
            got_value,
        | try std.testing.expect(want_value.eql(got_value));
    }
}
