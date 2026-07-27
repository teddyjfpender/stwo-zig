//! A shift row may not choose its own sign fill: `SRL` may not claim one at all,
//! and `SRA` may only claim the sign bit its operand actually carries.
//!
//! The forgery. `SRL x10, x5, x6` with `x5 = 0x04030201` and `x6 = 8` honestly
//! commits `result = 0x00040302` and `rs1_sign = 0`. A prover instead claims
//! `rs1_sign = 1`, which by the `input > 3` sign-fill equation forces the vacated
//! high byte `result[3] = 255`, i.e. the whole word `0xFF040302`. Every other
//! shift equation still closes: the shift is a whole limb, so `bit_multiplier`
//! is one and the `input == 3` equation's `rs1_sign * (bit_multiplier - 1)`
//! coefficient vanishes — `rs1_sign` reaches nothing but limb 3. All four result
//! limbs stay bytes, so the `range_check_8_8` pairs over the result cannot see
//! it. The symmetric claim on `SRA x11, x5, x6` is the same three columns: the
//! operand is positive, so `rs1_sign = 1` is a lie about bit 31.
//!
//! Why the two halves are guarded differently. `is_srl` and `is_sra` enter the
//! shift equations only through their sum `right_shift`, so on a right-shift row
//! `rs1_sign` is the *only* column whose meaning differs between the two
//! opcodes. Nothing else can distinguish them, and consequently neither guard
//! covers both rows:
//!
//!  - `(1 - is_sra) * rs1_sign` is a direct constraint, and on the `SRL` row it
//!    is the only guard there is — the `signRangeLookup` request carries
//!    numerator `-is_sra`, so it is switched *off* there;
//!  - on the `SRA` row that direct constraint vanishes identically, and the
//!    `signRangeLookup` request into `range_check_m31` is the only guard: it
//!    offers `{0, rs1.next[3] - rs1_sign * 128}`, and the table bounds the
//!    second element by 128, so a claimed sign the operand does not carry asks
//!    for a tuple that does not exist.
//!
//! The row-local tests probe that split rather than assuming it: the `SRL` test
//! asserts the forged row asks `range_check_m31` for nothing at all, and the
//! `SRA` test asserts every direct constraint vanishes and the sign request is
//! the only failing obligation. They are where this file's attribution lives,
//! and each fix has its own: deleting `(1 - is_sra) * rs1_sign` makes the forged
//! `SRL` row admissible and collapses the two opcodes' constraint vectors onto
//! each other, failing the two `SRL` tests and neither `SRA` one; deleting the
//! `signRangeLookup` request makes the forged `SRA` row admissible and fails
//! only its test.
//!
//! What the end-to-end tests do and do not show. They show the forged rows are
//! *reachable* — committed by the production witness path and refused in
//! production — and that the honest guest they are derived from proves and
//! verifies. Each is now pinned to the stage its own guard lives at, and the two
//! differ, which is the end-to-end shadow of the split above. The `SRL` row
//! breaks the direct constraint `(1 - is_sra) * rs1_sign`, so no proof exists:
//! `.prover_constraints`. The `SRA` row satisfies every direct constraint — the
//! row-local test below asserts exactly that — so it reaches a real proof and
//! loses the global LogUp closure: `.verification`.
//!
//! Neither is full attribution. Both forgeries also move `rd_next_3`, an element
//! of the register access tuple this row offers `memory_access`, so the `SRA`
//! row's verification failure could equally be the memory argument rather than
//! the sign range. Attribution stays row-local; what the stage pin adds is that
//! a lookup fix and a constraint fix are no longer indistinguishable end to end.
//!
//! Columns the forgery moves that the bug description does not name.
//! `destinationResultConstraints` pins `rd.next = rd_nonzero * result`, so
//! forging `result[3]` forces `rd_next_3` too. It is moved only to keep the row
//! self-consistent: without it the row fails that binding instead and the
//! rejection would say nothing about the sign fill.
//!
//! Why the row override exists. A single additive cell mutation cannot express
//! this row: raising `rs1_sign` alone leaves `result[3] = 0` and breaks the
//! sign-fill equation, so the row would be rejected with the fix deleted and the
//! test would guard nothing. See `prover/test_witness_hook.zig`.
//!
//! Runtime: four row-local cases in milliseconds, three end-to-end cases at
//! about thirty seconds each — one proof of an eleven-instruction guest,
//! dominated by the fixed-size preprocessed lookup tables rather than by the
//! guest. Bounded by construction: two committed `shifts_reg` rows.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");

const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");

/// The operand is the one public input word the fixture's prologue loads into
/// `x5`, read from the fixture rather than transcribed. Its high bit must be
/// clear: that is what makes `rs1_sign = 1` a lie on both rows.
const OPERAND: u32 = std.mem.readInt(u32, &guest_elf.INPUT, .little);
const SHIFT: u5 = 8;
const HONEST_RESULT: u32 = OPERAND >> SHIFT;
/// The high byte an arithmetic fill of a negative operand would leave behind,
/// and the value the `input > 3` equation forces once `rs1_sign` is one.
const SIGN_FILL: u32 = 0xFF;
/// `range_check_m31` bounds the second element of its tuple by this.
const SIGN_BOUND: u32 = 128;

comptime {
    std.debug.assert(OPERAND >> 31 == 0);
    // A whole-limb shift keeps `rs1_sign` out of result limb 2: see the header.
    std.debug.assert(SHIFT % 8 == 0);
}

/// `ADDI x6, x0, 8`, `SRL x10, x5, x6`, `SRA x11, x5, x6`.
///
/// `x5` holds the loaded input word and `x6` the shift amount; the prologue and
/// epilogue own `x1`, `x2`, `x4` and `x5`, so `x6`, `x10` and `x11` are free.
/// The epilogue publishes `x10`, the logical result.
const BODY = [_]u32{ 0x0080_0313, 0x0062_D533, 0x4062_D5B3 };
const SPEC = harness.Spec{ .body = &BODY };

/// Family-relative row index of each shift, in execution order.
const SRL_ROW: usize = 0;
const SRA_ROW: usize = 1;

// Every column the forgery touches, named through the committed layout so a
// reordered or renamed shift column is a compile error rather than a probe that
// silently lands on its neighbour.
const RS1_SIGN = layout.columnOf(.shifts_reg, "rs1_sign");
const RS1_NEXT_3 = layout.columnOf(.shifts_reg, "rs1_next_3");
const RESULT_3 = layout.columnOf(.shifts_reg, "result_3");
const RD_NEXT_3 = layout.columnOf(.shifts_reg, "rd_next_3");
const IS_SRL = layout.columnOf(.shifts_reg, "opcode_srl_flag");
const IS_SRA = layout.columnOf(.shifts_reg, "opcode_sra_flag");

/// Position of `(1 - is_sra) * rs1_sign` in `shift_common.evaluate` order:
/// `bit(enabler)`, then `bit` of the three opcode flags, then `bit(rs1_sign)`,
/// then the constraint under test. Counting emission order is how the number was
/// found, not why it is trusted: the test below re-derives it from the AIR as
/// the one index at which relabelling a row from `SRL` to `SRA` changes
/// anything.
const SIGN_WITHOUT_SRA: usize = 5;

/// The forged sign fill, identical on both rows: claim a sign bit the operand
/// does not have and carry the high byte it would have produced.
const SIGN_FILL_FORGERY = [_]harness.ColumnValue{
    .{ .column = RS1_SIGN, .value = 1 },
    .{ .column = RESULT_3, .value = SIGN_FILL },
    // Forced by `destinationResultConstraints`, not part of the false claim.
    .{ .column = RD_NEXT_3, .value = SIGN_FILL },
};

fn forgedRow(guest: *const harness.Guest, logical_row: usize) !harness.Row {
    var row = try guest.honestRow(.shifts_reg, logical_row);
    row.apply(&SIGN_FILL_FORGERY);
    return row;
}

fn override(logical_row: u32) harness.RowOverride {
    return .{
        .target = .{ .opcode = .{ .family = .shifts_reg } },
        .logical_row = logical_row,
        .values = &SIGN_FILL_FORGERY,
    };
}

/// The two honest committed shift rows, read out of the witness generator rather
/// than transcribed, so a witness-generation change moves the baseline instead
/// of desynchronising it from this test.
fn honestRows(guest: *const harness.Guest) ![2]harness.Row {
    try std.testing.expectEqual(@as(usize, 2), try guest.familyRowCount(.shifts_reg));
    return .{
        try guest.honestRow(.shifts_reg, SRL_ROW),
        try guest.honestRow(.shifts_reg, SRA_ROW),
    };
}

// Runtime: milliseconds. One eleven-instruction run and two 60-column rows.
test "shift sign: the honest SRL and SRA rows carry sign zero and are admissible" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestRows(&guest);

    for (honest, [_]usize{ IS_SRL, IS_SRA }) |row, selector| {
        try harness.expectAccepted(.shifts_reg, row.slice());
        // The rows are the two opcodes this file is about, in this order.
        try std.testing.expectEqual(M31.one(), row.m31At(selector));
        // The operand's high byte is below 128 and the committed sign is zero:
        // the two facts the forgeries contradict.
        try std.testing.expectEqual(M31.fromCanonical(OPERAND >> 24), row.m31At(RS1_NEXT_3));
        try std.testing.expect(OPERAND >> 24 < SIGN_BOUND);
        try std.testing.expectEqual(M31.zero(), row.m31At(RS1_SIGN));
        try std.testing.expectEqual(M31.fromCanonical(HONEST_RESULT >> 24), row.m31At(RESULT_3));
    }

    // The column the forgery must also move to stay self-consistent is the one
    // the register access block — and therefore `memory_access` — reads.
    try std.testing.expectEqual(layout.nextLimbColumn(.shifts_reg, 0, 3), RD_NEXT_3);
}

// Runtime: milliseconds. Same shape as the test above.
test "shift sign: the direct constraints tell SRL from SRA nowhere but the sign guard" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    // Relabelling one row from `SRL` to `SRA` leaves `enabler` and `right_shift`
    // — the only forms in which the two flags reach any other equation — fixed,
    // so the whole evaluation is fixed apart from the constraint under test.
    // That is the hole this fix closed, stated as an assertion: with the
    // constraint gone the two opcodes have bit-identical constraint vectors and
    // nothing at all decides which one a right-shift row is. It also derives
    // `SIGN_WITHOUT_SRA` from the AIR, so a reordered `shift_common` moves the
    // pin instead of silently aiming the attribution below at a neighbour.
    const as_srl = try forgedRow(&guest, SRL_ROW);
    var as_sra = as_srl;
    as_sra.apply(&.{
        .{ .column = IS_SRL, .value = 0 },
        .{ .column = IS_SRA, .value = 1 },
    });

    const srl = try semantic_eval.evaluate(.shifts_reg, as_srl.slice(), QM31.one());
    const sra = try semantic_eval.evaluate(.shifts_reg, as_sra.slice(), QM31.one());
    try std.testing.expectEqual(srl.len, sra.len);
    for (srl.values[0..srl.len], sra.values[0..sra.len], 0..) |left, right, index| {
        if (index == SIGN_WITHOUT_SRA) continue;
        try std.testing.expect(left.eql(right));
    }
    // The claimed sign is what the constraint sees, and only `SRA` may carry it.
    try std.testing.expect(srl.values[SIGN_WITHOUT_SRA].eql(QM31.one()));
    try std.testing.expect(sra.values[SIGN_WITHOUT_SRA].isZero());
}

// Runtime: milliseconds. Same shape as the test above.
test "shift sign: the forged SRL row fails only the (1 - is_sra) * rs1_sign constraint" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const forged = try forgedRow(&guest, SRL_ROW);

    // The forged word is the attack: a logical shift that zero-fills has claimed
    // an arithmetic sign extension.
    try std.testing.expectEqual(M31.fromCanonical(SIGN_FILL), forged.m31At(RESULT_3));

    // `signRangeLookup` carries numerator `-is_sra`, which is zero here, so the
    // forged row asks `range_check_m31` for nothing and the direct constraint is
    // the only guard there is. This is the probe behind the split this file
    // claims, not an assumption: an empty fingerprint is what a row that emits
    // no activated request to a relation hashes to.
    try std.testing.expectEqual(
        try harness.busFingerprint(.shifts_reg, forged.slice(), .range_check_m31),
        std.hash.Wyhash.hash(0, ""),
    );

    try harness.expectOnlyConstraint(.shifts_reg, forged.slice(), SIGN_WITHOUT_SRA);
}

// Runtime: milliseconds. Same shape as the test above.
test "shift sign: the forged SRA row fails only the range_check_m31 sign binding" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = (try honestRows(&guest))[SRA_ROW];
    const forged = try forgedRow(&guest, SRA_ROW);

    // `(1 - is_sra) * rs1_sign` vanishes on an SRA row, so the direct
    // constraints admit this word: `expectOnlyLookup` asserts the whole
    // evaluation is zero, which is what makes the rejection attributable to the
    // sign range rather than to a carry chain or a destination write.
    const rejection = try harness.expectOnlyLookup(
        .shifts_reg,
        forged.slice(),
        .range_check_m31,
    );
    // `{0, rs1.next[3] - rs1_sign * 128}`: the tuple that proves `rs1_sign` is
    // bit 31, since `range_check_m31` bounds its second element by 128. The
    // operand's high byte is 4, so the claimed sign asks the table for `4 - 128`.
    try std.testing.expectEqual(@as(usize, 2), rejection.tuple().len);
    try std.testing.expectEqual(M31.zero(), rejection.tuple()[0].tryIntoM31() catch unreachable);
    try std.testing.expectEqual(
        M31.fromCanonical(OPERAND >> 24).sub(M31.fromCanonical(SIGN_BOUND)),
        rejection.tuple()[1].tryIntoM31() catch unreachable,
    );
    try std.testing.expect((OPERAND >> 24) < SIGN_BOUND);

    // Attribution has to be row-local: the forced `rd_next_3` is an element of
    // the register access tuple this row offers `memory_access`, so no
    // end-to-end forgery can isolate the sign range. See the header.
    try std.testing.expect(
        try harness.busFingerprint(.shifts_reg, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.shifts_reg, forged.slice(), .memory_access),
    );
    // The claim is specific to that bus: the row's state-chain and program
    // tuples are untouched, so the difference above is the register write.
    try std.testing.expectEqual(
        try harness.busFingerprint(.shifts_reg, honest.slice(), .registers_state),
        try harness.busFingerprint(.shifts_reg, forged.slice(), .registers_state),
    );
    try std.testing.expectEqual(
        try harness.busFingerprint(.shifts_reg, honest.slice(), .program_access),
        try harness.busFingerprint(.shifts_reg, forged.slice(), .program_access),
    );
}

// Runtime: about thirty seconds — one proof and one verification.
test "shift sign end-to-end: the honest SRL and SRA guest proves and verifies" {
    // Without this the two rejection tests below would also be satisfied by a
    // guest that cannot be proven at all. Before this file nothing in the
    // repository proved a `shifts_reg` row end to end.
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    // A positive operand shifts the same way both ways, which is what makes
    // `rs1_sign = 1` a lie on either row.
    try std.testing.expectEqual(HONEST_RESULT, guest.run.final_regs[10]);
    try std.testing.expectEqual(HONEST_RESULT, guest.run.final_regs[11]);
    try guest.proveAndVerify("shift sign guest (SRL and SRA of a positive word)");
}

// Runtime: about thirty seconds — one rejected proof attempt.
test "shift sign end-to-end: the forged SRL row never becomes a proof" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    // `(1 - is_sra) * rs1_sign` is a direct constraint, so the row never becomes
    // a proof. That is the stage a constraint fix belongs at, and it is what
    // separates this case from the `SRA` one below.
    try guest.expectRejectedAt(.{ .main_row = override(SRL_ROW) }, .prover_constraints);
}

// Runtime: about thirty seconds — one rejected proof attempt.
test "shift sign end-to-end: the forged SRA row proves and loses at verification" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    // The fix that catches this row is a lookup request, so it must survive
    // proving and lose at verification — and it does. The `signRangeLookup`
    // tuple `{0, rs1.next[3] - 128}` has no row in `range_check_m31`, so its
    // opcode-side fraction has nothing to cancel against.
    try guest.expectRejectedAt(.{ .main_row = override(SRA_ROW) }, .verification);
}
