const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const candidate = @import("typed_two_read_register_alias_candidate_v1.zig");
const lt_authority = @import("typed_lt_reg_authority.zig");
const lt_support = @import("typed_lt_reg_witness_test_support.zig");
const lt_witness = @import("typed_lt_reg_witness.zig");
const mul_authority = @import("typed_mul_authority.zig");
const mul_corpus = @import("typed_mul_corpus.zig");
const mul_witness = @import("typed_mul_witness.zig");
const mulh_authority = @import("typed_mulh_authority.zig");
const mulh_support = @import("typed_mulh_witness_test_support.zig");
const mulh_witness = @import("typed_mulh_witness.zig");
const Opcode = @import("../../runner/decode.zig").Opcode;

test "two-read alias profiles bind three distinct fixed family programs" {
    const lt = candidate.profile(.lt_reg);
    const mul = candidate.profile(.mul);
    const mulh = candidate.profile(.mulh);
    try lt.validate();
    try mul.validate();
    try mulh.validate();
    try std.testing.expect(!candidate.production_active);
    try std.testing.expectEqual(@as(u8, 36), lt.main_column_count);
    try std.testing.expectEqual(@as(u8, 28), lt.direct_constraint_count);
    try std.testing.expectEqual(@as(u8, 31), mul.main_column_count);
    try std.testing.expectEqual(@as(u8, 9), mul.direct_constraint_count);
    try std.testing.expectEqual(@as(u8, 39), mulh.main_column_count);
    try std.testing.expectEqual(@as(u8, 16), mulh.direct_constraint_count);
    try expectDistinct(&lt.verifier_program_identity, &mul.verifier_program_identity);
    try expectDistinct(&lt.verifier_program_identity, &mulh.verifier_program_identity);
    try expectDistinct(&mul.verifier_program_identity, &mulh.verifier_program_identity);

    var malformed = lt;
    malformed.aliases[0].source_column +%= 1;
    try expectInvalidProfile(&malformed);
    malformed = mul;
    malformed.removed_direct_roots[7] -%= 1;
    try expectInvalidProfile(&malformed);
    malformed = mulh;
    malformed.verifier_program_identity[0] ^= 1;
    try expectInvalidProfile(&malformed);
}

test "LT_REG alias preserves SLT and SLTU roots and ordered relations" {
    const cases = [_]struct { opcode: Opcode, lhs: u32, rhs: u32 }{
        .{ .opcode = .SLT, .lhs = 0xffff_ffff, .rhs = 0 },
        .{ .opcode = .SLTU, .lhs = 0xffff_ffff, .rhs = 0 },
    };
    for (cases, 0..) |case, index| {
        const row = lt_support.makeRow(
            case.opcode,
            7,
            5,
            6,
            case.lhs,
            case.rhs,
            @intCast(20 + index),
            @intCast(0x1000 + 4 * index),
            0x1122_3344,
            1,
            2,
            3,
        );
        const canonical_m31 = ltCanonical(row);
        const compact_m31 = try candidate.project(.lt_reg, canonical_m31);
        const canonical = toQM31(canonical_m31);
        const compact = toQM31(compact_m31);
        try expectScalarSlicesEqual(
            &canonical,
            &candidate.expand(.lt_reg, QM31, compact),
        );
        const program = try lt_authority.Authority.pinned().buildProgram(
            QM31,
            &canonical,
            QM31.one(),
        );
        const direct = try candidate.ltRegDirect(QM31, compact, QM31.one());
        try expectScalarSlicesEqual(
            &candidate.filterCanonicalDirect(
                .lt_reg,
                QM31,
                program.direct_constraints.values,
            ),
            &direct,
        );
        for (direct) |root| try std.testing.expect(root.isZero());
        try expectLookupsEqual(
            program.lookup_entries,
            try candidate.ltRegLookups(QM31, compact),
        );
    }

    var forged = ltCanonical(lt_support.makeRow(
        .SLT,
        7,
        5,
        6,
        1,
        2,
        20,
        0x1000,
        0,
        1,
        2,
        3,
    ));
    forged[18] = forged[18].add(M31.one());
    try expectAliasMismatch(.lt_reg, forged);
}

test "MUL alias preserves low-word product roots and ordered relations" {
    const cases = [_]usize{ 0, 17, 127, mul_corpus.CORPUS_ROW_COUNT - 1 };
    for (cases) |case_index| {
        const canonical_m31 = mulCanonical(mul_corpus.traceRow(case_index));
        const compact_m31 = try candidate.project(.mul, canonical_m31);
        const canonical = toQM31(canonical_m31);
        const compact = toQM31(compact_m31);
        try expectScalarSlicesEqual(
            &canonical,
            &candidate.expand(.mul, QM31, compact),
        );
        const program = try mul_authority.Authority.pinned().buildProgram(
            QM31,
            &canonical,
            QM31.one(),
        );
        const direct = try candidate.mulDirect(QM31, compact, QM31.one());
        try expectScalarSlicesEqual(
            &candidate.filterCanonicalDirect(
                .mul,
                QM31,
                program.direct_constraints.values,
            ),
            &direct,
        );
        for (direct) |root| try std.testing.expect(root.isZero());
        try expectLookupsEqual(
            program.lookup_entries,
            try candidate.mulLookups(QM31, compact),
        );
    }

    var forged = mulCanonical(mul_corpus.traceRow(1));
    forged[32] = forged[32].add(M31.one());
    try expectAliasMismatch(.mul, forged);
}

test "MULH alias preserves all high-word opcode roots and ordered relations" {
    for (mulh_support.operations, 0..) |opcode, index| {
        const row = mulh_support.makeRow(
            opcode,
            7,
            5,
            6,
            0x8000_0001 +% @as(u32, @intCast(index)),
            0xffff_fffe -% @as(u32, @intCast(index)),
            @intCast(30 + index),
            @intCast(0x2000 + 4 * index),
            0x1122_3344,
            1,
            2,
            3,
        );
        const canonical_m31 = mulhCanonical(row);
        const compact_m31 = try candidate.project(.mulh, canonical_m31);
        const canonical = toQM31(canonical_m31);
        const compact = toQM31(compact_m31);
        try expectScalarSlicesEqual(
            &canonical,
            &candidate.expand(.mulh, QM31, compact),
        );
        const program = try mulh_authority.Authority.pinned().buildProgram(
            QM31,
            &canonical,
            QM31.one(),
        );
        const direct = try candidate.mulhDirect(QM31, compact, QM31.one());
        try expectScalarSlicesEqual(
            &candidate.filterCanonicalDirect(
                .mulh,
                QM31,
                program.direct_constraints.values,
            ),
            &direct,
        );
        for (direct) |root| try std.testing.expect(root.isZero());
        try expectLookupsEqual(
            program.lookup_entries,
            try candidate.mulhLookups(QM31, compact),
        );
    }

    var forged = mulhCanonical(mulh_support.makeRow(
        .MULHU,
        7,
        5,
        6,
        1,
        2,
        30,
        0x2000,
        0,
        1,
        2,
        3,
    ));
    forged[28] = forged[28].add(M31.one());
    try expectAliasMismatch(.mulh, forged);
}

test "two-read aliases project exact retained padded corpus savings" {
    const projection = try candidate.projectRetainedCost(.{
        .lt_reg = 13_218_896,
        .mul = 10_266_688,
        .mulh = 9_863_712,
    });
    try std.testing.expectEqual(
        @as(u64, 105_751_168),
        projection.lt_reg_saved_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 82_133_504),
        projection.mul_saved_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 78_909_696),
        projection.mulh_saved_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 266_794_368),
        projection.saved_main_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 1_067_177_472),
        projection.saved_raw_bytes,
    );
}

fn ltCanonical(row: lt_witness.TraceRow) [lt_witness.MAIN_COLUMN_COUNT]M31 {
    var storage: [lt_witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var views: [lt_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*owned, *view| view.* = owned;
    lt_witness.writeActiveRow(&views, 0, row);
    return firstRow(lt_witness.MAIN_COLUMN_COUNT, storage);
}

fn mulCanonical(row: mul_witness.TraceRow) [mul_witness.MAIN_COLUMN_COUNT]M31 {
    var storage: [mul_witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var views: [mul_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*owned, *view| view.* = owned;
    mul_witness.writeActiveRow(&views, 0, row);
    return firstRow(mul_witness.MAIN_COLUMN_COUNT, storage);
}

fn mulhCanonical(row: mulh_witness.TraceRow) [mulh_witness.MAIN_COLUMN_COUNT]M31 {
    var storage: [mulh_witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var views: [mulh_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*owned, *view| view.* = owned;
    mulh_witness.writeActiveRow(&views, 0, row);
    return firstRow(mulh_witness.MAIN_COLUMN_COUNT, storage);
}

fn firstRow(comptime width: usize, storage: [width][1]M31) [width]M31 {
    var result: [width]M31 = undefined;
    for (&result, storage) |*value, cell| value.* = cell[0];
    return result;
}

fn toQM31(values: anytype) [values.len]QM31 {
    var result: [values.len]QM31 = undefined;
    for (&result, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return result;
}

fn expectAliasMismatch(comptime family: candidate.Family, canonical: anytype) !void {
    try std.testing.expectError(
        error.RegisterReadAliasMismatch,
        candidate.project(family, canonical),
    );
}

fn expectInvalidProfile(value: *const candidate.ProfileV1) !void {
    try std.testing.expectError(
        error.InvalidTwoReadRegisterAliasProfile,
        value.validate(),
    );
}

fn expectDistinct(lhs: *const candidate.Digest, rhs: *const candidate.Digest) !void {
    try std.testing.expect(!std.mem.eql(u8, lhs, rhs));
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
