//! End-to-end committed-row coverage for the eight previously unexercised
//! opcode families: `base_alu_imm`, `branch_lt`, `fence`, `jal`, `lt_imm`,
//! `lt_reg`, `mul`, and `shifts_imm`.
//!
//! Each case reads its honest row from the production witness generator,
//! attributes a semantic forgery locally where that is possible, requires the
//! forged committed pipeline to reject it, and finally proves and verifies the
//! honest guest. Writes target x0 wherever the family permits it. That leaves
//! the architectural buses byte-identical and makes the direct constraint or
//! range-table request named by the test the only possible rejection.
//!
//! FENCE is the deliberate exception. Its reserved decoded fields have no
//! direct constraint: they are bound to the fetched instruction exclusively by
//! `program_access`. The FENCE test therefore proves local admissibility,
//! isolates the changed program-bus fingerprint, and pins rejection to
//! verification.

const std = @import("std");

const harness = @import("committed_forgery_harness.zig");
const guest_elf = @import("guest_elf_fixture.zig");
const layout = @import("committed_row_layout.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");

const OpcodeFamily = harness.OpcodeFamily;

fn columnOf(comptime family: OpcodeFamily, comptime name: []const u8) u32 {
    return @intCast(layout.columnOf(family, name));
}

fn honestBodyRow(
    guest: *const harness.Guest,
    family: OpcodeFamily,
    expected_family_rows: usize,
) !harness.Row {
    try std.testing.expectEqual(expected_family_rows, try guest.familyRowCount(family));
    const row = try guest.honestRow(family, 0);
    try harness.expectAccepted(family, row.slice());
    return row;
}

fn expectOnlyConstraint(
    family: OpcodeFamily,
    row: *const harness.Row,
    index: usize,
    total: usize,
) !void {
    try std.testing.expectEqual(total, semantic_eval.constraintCount(family));
    try harness.expectOnlyConstraint(family, row.slice(), index);
}

fn expectAllBusesUnchanged(
    family: OpcodeFamily,
    honest: *const harness.Row,
    forged: *const harness.Row,
) !void {
    for ([_]harness.Domain{
        .memory_access,
        .registers_state,
        .program_access,
    }) |domain| {
        try std.testing.expectEqual(
            try harness.busFingerprint(family, honest.slice(), domain),
            try harness.busFingerprint(family, forged.slice(), domain),
        );
    }
}

fn rejectThenProveHonest(
    guest: *const harness.Guest,
    family: OpcodeFamily,
    values: []const harness.ColumnValue,
    stage: harness.RejectionStage,
    label: []const u8,
) !void {
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = family } },
        .logical_row = 0,
        .values = values,
    } }, stage);
    // Last: a missing pinned Sail oracle may skip only after every
    // Sail-independent forgery obligation has already passed.
    try guest.proveAndVerify(label);
}

// All writing fixtures target x0. Their computed result remains committed and
// constrained, while `rd.next` and the register bus remain honestly zero.
const ADDI_X0_X5_7: u32 = 0x0072_8013;
const BLTU_X0_X0_PLUS_4: u32 = 0x0000_6263;
const FENCE_RESERVED: u32 = 0x0FF0_000F;
const JAL_X0_PLUS_4: u32 = 0x0040_006F;
const SLTIU_X0_X0_0: u32 = 0x0000_3013;
const SLTU_X0_X5_X5: u32 = 0x0052_B033;
const MUL_X0_X5_X5: u32 = 0x0252_8033;
const SLLI_X0_X5_1: u32 = 0x0012_9013;

const BASE_SPEC = harness.Spec{ .body = &.{ADDI_X0_X5_7}, .publish = 5 };
const BRANCH_SPEC = harness.Spec{ .body = &.{BLTU_X0_X0_PLUS_4}, .publish = 5 };
const FENCE_SPEC = harness.Spec{ .body = &.{FENCE_RESERVED}, .publish = 5 };
const JAL_SPEC = harness.Spec{ .body = &.{JAL_X0_PLUS_4}, .publish = 5 };
const LT_IMM_SPEC = harness.Spec{ .body = &.{SLTIU_X0_X0_0}, .publish = 5 };
const LT_REG_SPEC = harness.Spec{ .body = &.{SLTU_X0_X5_X5}, .publish = 5 };
const MUL_SPEC = harness.Spec{ .body = &.{MUL_X0_X5_X5}, .publish = 5 };
const SHIFTS_IMM_SPEC = harness.Spec{ .body = &.{SLLI_X0_X5_1}, .publish = 5 };

test "committed family base_alu_imm: wrong ADDI high byte is rejected and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, BASE_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .base_alu_imm, 3);

    const result_3 = columnOf(.base_alu_imm, "result_3");
    try std.testing.expectEqual(@as(u32, 4), honest.m31At(result_3).toU32());
    const values = [_]harness.ColumnValue{
        .{ .column = result_3, .value = 5 },
    };
    var forged = honest;
    forged.apply(&values);

    // Constraint 9 is the fourth and final ADDI carry-bit constraint:
    // 0..4 flag bits, 5 immediate sign, 6..9 byte carries.
    try expectOnlyConstraint(.base_alu_imm, &forged, 9, 22);
    try expectAllBusesUnchanged(.base_alu_imm, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .base_alu_imm,
        &values,
        .prover_constraints,
        "committed base_alu_imm guest (ADDI x0, x5, 7)",
    );
}

test "committed family branch_lt: false equal-operand comparison is rejected and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, BRANCH_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .branch_lt, 1);

    const cmp_result = columnOf(.branch_lt, "cmp_result");
    const cmp_lt = columnOf(.branch_lt, "cmp_lt");
    const branch_target = columnOf(.branch_lt, "branch_target");
    try std.testing.expectEqual(@as(u32, 0), honest.m31At(cmp_result).toU32());
    try std.testing.expectEqual(@as(u32, 0), honest.m31At(cmp_lt).toU32());
    // Taken and not-taken both advance by four for this instruction, so the
    // forged comparison changes no state-bus tuple.
    try std.testing.expectEqual(
        guest_elf.bodyPc(0) + 4,
        honest.m31At(branch_target).toU32(),
    );
    const values = [_]harness.ColumnValue{
        .{ .column = cmp_result, .value = 1 },
        .{ .column = cmp_lt, .value = 1 },
    };
    var forged = honest;
    forged.apply(&values);

    // Constraint 22 says an equal comparison (no diff marker) cannot be less.
    try expectOnlyConstraint(.branch_lt, &forged, 22, 33);
    try expectAllBusesUnchanged(.branch_lt, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .branch_lt,
        &values,
        .prover_constraints,
        "committed branch_lt guest (BLTU x0, x0, +4)",
    );
}

test "committed family fence: forged reserved field loses on the program bus and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, FENCE_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .fence, 1);

    const immediate = columnOf(.fence, "immediate");
    const forged_immediate = honest.m31At(immediate).toU32() + 1;
    try std.testing.expect(forged_immediate < (1 << 12));
    const values = [_]harness.ColumnValue{
        .{ .column = immediate, .value = forged_immediate },
    };
    var forged = honest;
    forged.apply(&values);

    // FENCE intentionally delegates this binding to the decoded-program bus:
    // there is no row-local table or direct constraint to name.
    try harness.expectAccepted(.fence, forged.slice());
    try std.testing.expect(
        try harness.busFingerprint(.fence, honest.slice(), .program_access) !=
            try harness.busFingerprint(.fence, forged.slice(), .program_access),
    );
    for ([_]harness.Domain{ .memory_access, .registers_state }) |domain| {
        try std.testing.expectEqual(
            try harness.busFingerprint(.fence, honest.slice(), domain),
            try harness.busFingerprint(.fence, forged.slice(), domain),
        );
    }
    try rejectThenProveHonest(
        &guest,
        .fence,
        &values,
        .verification,
        "committed fence guest (reserved-field FENCE no-op)",
    );
}

test "committed family jal: forged link address is rejected and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, JAL_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .jal, 1);

    const result_0 = columnOf(.jal, "result_0");
    const honest_link = guest_elf.bodyPc(0) + 4;
    const forged_link = guest_elf.bodyPc(0) + 8;
    try std.testing.expectEqual(honest_link & 0xff, honest.m31At(result_0).toU32());
    // Both addresses have identical upper bytes for the fixture's body PC.
    try std.testing.expectEqual(honest_link >> 8, forged_link >> 8);
    const values = [_]harness.ColumnValue{
        .{ .column = result_0, .value = forged_link & 0xff },
    };
    var forged = honest;
    forged.apply(&values);

    // Constraint 1 binds the committed link word to pc + 4.
    try expectOnlyConstraint(.jal, &forged, 1, 10);
    try expectAllBusesUnchanged(.jal, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .jal,
        &values,
        .prover_constraints,
        "committed jal guest (JAL x0, +4)",
    );
}

test "committed family lt_imm: false equality comparison is rejected and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, LT_IMM_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .lt_imm, 1);

    const cmp_result = columnOf(.lt_imm, "cmp_result");
    try std.testing.expectEqual(@as(u32, 0), honest.m31At(cmp_result).toU32());
    const values = [_]harness.ColumnValue{
        .{ .column = cmp_result, .value = 1 },
    };
    var forged = honest;
    forged.apply(&values);

    // Constraint 19 forbids claiming x0 < 0 when no differing limb exists.
    try expectOnlyConstraint(.lt_imm, &forged, 19, 33);
    try expectAllBusesUnchanged(.lt_imm, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .lt_imm,
        &values,
        .prover_constraints,
        "committed lt_imm guest (SLTIU x0, x0, 0)",
    );
}

test "committed family lt_reg: false equality comparison is rejected and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, LT_REG_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .lt_reg, 1);

    const cmp_result = columnOf(.lt_reg, "cmp_result");
    try std.testing.expectEqual(@as(u32, 0), honest.m31At(cmp_result).toU32());
    const values = [_]harness.ColumnValue{
        .{ .column = cmp_result, .value = 1 },
    };
    var forged = honest;
    forged.apply(&values);

    // Constraint 19 forbids claiming x5 < x5 with no differing limb.
    try expectOnlyConstraint(.lt_reg, &forged, 19, 36);
    try expectAllBusesUnchanged(.lt_reg, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .lt_reg,
        &values,
        .prover_constraints,
        "committed lt_reg guest (SLTU x0, x5, x5)",
    );
}

test "committed family mul: false product loses only on carry range and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, MUL_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .mul, 1);

    const result_0 = columnOf(.mul, "result_0");
    try std.testing.expectEqual(@as(u32, 1), honest.m31At(result_0).toU32());
    const values = [_]harness.ColumnValue{
        .{ .column = result_0, .value = 2 },
    };
    var forged = honest;
    forged.apply(&values);

    // MUL has no direct multiplication constraint. The first product carry is
    // request 9 after program, state, and the two three-entry source accesses.
    const rejection = try harness.expectOnlyLookup(
        .mul,
        forged.slice(),
        .range_check_8_11,
    );
    try std.testing.expectEqual(@as(usize, 9), rejection.index);
    try std.testing.expectEqual(@as(u32, 2), (try rejection.tuple()[0].tryIntoM31()).toU32());
    try std.testing.expect(
        (try rejection.tuple()[1].tryIntoM31()).toU32() >= (1 << 11),
    );
    try expectAllBusesUnchanged(.mul, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .mul,
        &values,
        .verification,
        "committed mul guest (MUL x0, x5, x5)",
    );
}

test "committed family shifts_imm: wrong SLLI high byte is rejected and honest proof verifies" {
    var guest = try harness.Guest.init(std.testing.allocator, SHIFTS_IMM_SPEC);
    defer guest.deinit();
    const honest = try honestBodyRow(&guest, .shifts_imm, 1);

    const result_3 = columnOf(.shifts_imm, "result_3");
    // The fixture loads x5 = 0x04030201 from its declared input image, so
    // SLLI x0, x5, 1 commits 0x08060402 while discarding the register write.
    try std.testing.expectEqual(@as(u32, 8), honest.m31At(result_3).toU32());
    const values = [_]harness.ColumnValue{
        .{ .column = result_3, .value = 9 },
    };
    var forged = honest;
    forged.apply(&values);

    // Constraints 22..37 are the 4 x 4 left-shift equations. For a one-bit
    // shift limb marker 0 is active, and index 25 is its high-byte equation.
    try expectOnlyConstraint(.shifts_imm, &forged, 25, 67);
    try expectAllBusesUnchanged(.shifts_imm, &honest, &forged);
    try rejectThenProveHonest(
        &guest,
        .shifts_imm,
        &values,
        .prover_constraints,
        "committed shifts_imm guest (SLLI x0, x5, 1)",
    );
}
