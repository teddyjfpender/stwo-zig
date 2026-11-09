//! A `DIVU` divisor whose limbs are not bytes is rejected, and rejected *by* the
//! divisor byte range check rather than incidentally.
//!
//! The forgery. `DIVU x10, x8, x9` with `x8 = 100`, `x9 = 2` honestly commits
//! `q = 50, r = 0` and divisor limbs `[2, 0, 0, 0]`. A prover instead claims
//! `q = 0, r = 100` and carries the divisor in limbs `[0, 0, 0, 256]`. Those
//! limbs compose to `256 * 2^24 = 2^32`, and `2^32 == 2 (mod 2^31 - 1)`, so the
//! divisor's *field* value is still 2 while its limbs are not bytes. Every
//! direct equation then holds: the recurrence `100 = 2 * 0 + 100` closes with
//! all eight product carries zero, and the remainder bound `r < c` is faked in
//! the top limb, where `diffs[3] = 256 - 0` is positive, so `lt_diff = 256`
//! passes the loose `range_check_20` bound the scan relies on.
//!
//! Why attribution is the whole point. A rejection is only evidence for the two
//! `divisor_ranges` requests if nothing else rejects first. So the first test
//! asserts the direct constraints all vanish and that the *only* failing
//! obligation is `range_check_8_8` on the divisor's high limb pair; delete those
//! two requests and this test fails. The second test claims the same false
//! `q = 0, r = 100` with honest byte limbs `[2, 0, 0, 0]` and shows it is caught
//! by `range_check_20` on `lt_diff` instead — which is exactly the check the
//! non-byte limbs evade, and therefore why byte-ranging the divisor is what
//! closes the hole.
//!
//! What the end-to-end test does and does not show. A row-local verdict does not
//! say a `div` row can be committed and proven at all, and until this file
//! nothing in the repository proved one; the last test closes that. It cannot,
//! however, attribute its rejection to `divisor_ranges`, and the test before it
//! proves why: every value those two requests range-check is also an element of
//! the register access tuples the row offers to `memory_access`, so a non-byte
//! limb moves that bus and the global memory argument rejects the row whatever
//! the byte range does. `divisor_ranges` is row-local hardening — it makes the
//! `div` AIR sound without relying on the global memory argument and on every
//! producing family byte-ranging its writes — and the row-local tests are the
//! only place that property is observable.
//!
//! Why the stage is `.verification`. A fix that lives in a lookup request must
//! survive proving and lose at the global LogUp closure, and this one does: the
//! forged row satisfies every direct constraint, so `main_trace` commits it, the
//! interaction trace is derived from it, and the missing `range_check_8_8`
//! multiplicity leaves the total sum non-zero. That was unreachable while the
//! mutation hook applied `.main_row` to the duplicated committed columns after
//! Tree 2 had already been generated from the honest witness; it now applies to
//! the workspace buffers ahead of both. See `prover/test_witness_hook.zig`.
//!
//! Why the row override exists. A single additive cell mutation cannot express
//! this row: raising `rs2_next_3` alone breaks the read-only access binding
//! (`next == previous`) and the product carry chain, so the row would be
//! rejected with the byte range deleted and the test would guard nothing. See
//! `prover/test_witness_hook.zig`.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;

const divu_fixture = @import("divu_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");

const divu = divu_fixture.divu;

// Every column the forgery touches, named through the committed layout so a
// reordered or renamed `div` column is a compile error rather than a probe that
// silently lands on its neighbour.
const RS2_SLOT: usize = 2;
const RS2_PREVIOUS = limbColumns("rs2_prev");
const RS2_NEXT = limbColumns("rs2_next");
const RD_NEXT = limbColumns("rd_next");
const Q = limbColumns("q");
const R = limbColumns("r");
const R_ABS = limbColumns("r_abs");
const R_INV = limbColumns("r_inv");
const LT_MARKER = limbColumns("lt_marker");
const R_ZERO = layout.columnOf(.div, "r_zero");
const C_SUM_INV = layout.columnOf(.div, "c_sum_inv");
const R_SUM_INV = layout.columnOf(.div, "r_sum_inv");
const LT_DIFF = layout.columnOf(.div, "lt_diff");

fn limbColumns(comptime prefix: []const u8) [4]usize {
    return .{
        layout.columnOf(.div, prefix ++ "_0"),
        layout.columnOf(.div, prefix ++ "_1"),
        layout.columnOf(.div, prefix ++ "_2"),
        layout.columnOf(.div, prefix ++ "_3"),
    };
}

fn inverse(value: u32) u32 {
    return M31.fromCanonical(value).invUncheckedNonZero().toU32();
}

/// Absolute committed values for one forged row, bounded by the columns the
/// forgery names. Appending a column twice is a caller error the hook rejects,
/// so each helper below writes disjoint columns.
const Forgery = struct {
    /// Eighteen columns move at most: the seven-column quotient/remainder claim,
    /// four divisor `previous`, four divisor `next`, and the three columns the
    /// remainder-bound scan needs.
    const CAPACITY: usize = 20;

    buffer: [CAPACITY]harness.ColumnValue = undefined,
    len: usize = 0,

    fn set(self: *Forgery, column: usize, value: u32) void {
        self.buffer[self.len] = .{ .column = @intCast(column), .value = value };
        self.len += 1;
    }

    fn setLimbs(self: *Forgery, columns: [4]usize, limbs: [4]u32) void {
        for (columns, limbs) |column, value| self.set(column, value);
    }

    fn values(self: *const Forgery) []const harness.ColumnValue {
        return self.buffer[0..self.len];
    }
};

/// `q = 0, r = 100` for `100 / 2`: the false claim both forgeries make.
///
/// `r != 0` switches off `r_zero`, which turns on the regular-case remainder
/// bound (`valid_not_special`) and therefore requires `r_sum_inv`. `sign_xor`
/// is zero for `DIVU`, so `r_abs == r`; `r_inv[0]` is recomputed from
/// `(r_abs[0] - 256)^-1` even though the sign-negation constraints that read it
/// are switched off, so the row is what an honest prover would have emitted for
/// these values rather than a mix of two witnesses.
fn falseQuotientClaim(forgery: *Forgery) void {
    forgery.set(RD_NEXT[0], 0);
    forgery.set(Q[0], 0);
    forgery.set(R[0], divu.DIVIDEND);
    forgery.set(R_ABS[0], divu.DIVIDEND);
    forgery.set(R_ZERO, 0);
    forgery.set(R_SUM_INV, inverse(divu.DIVIDEND));
    forgery.set(R_INV[0], inverse(m31.Modulus - (256 - divu.DIVIDEND)));
}

/// The false claim carried by non-byte divisor limbs `[0, 0, 0, 256]`.
fn nonByteDivisorForgery() Forgery {
    var forgery = Forgery{};
    falseQuotientClaim(&forgery);
    // Read-only source registers force `previous == next`, so both blocks move.
    forgery.setLimbs(RS2_PREVIOUS, NON_BYTE_DIVISOR_LIMBS);
    forgery.setLimbs(RS2_NEXT, NON_BYTE_DIVISOR_LIMBS);
    forgery.set(C_SUM_INV, inverse(256));
    // The high-to-low scan closes on limb 3, where the non-byte limb makes
    // `diffs[3] = 256 - 0` positive and so reports `r < c` falsely.
    forgery.set(LT_MARKER[3], 1);
    forgery.set(LT_DIFF, 256);
    return forgery;
}

/// The same false claim with the honest byte-decomposed divisor `[2, 0, 0, 0]`.
fn byteDivisorForgery() Forgery {
    var forgery = Forgery{};
    falseQuotientClaim(&forgery);
    // Divisor limbs untouched. The scan now closes on limb 0, where
    // `diffs[0] = 2 - 100` is negative, so the only `lt_diff` the markers admit
    // is `-98`, whose `range_check_20` request is out of range.
    forgery.set(LT_MARKER[0], 1);
    forgery.set(LT_DIFF, m31.Modulus - (divu.DIVIDEND - divu.DIVISOR));
    return forgery;
}

const NON_BYTE_DIVISOR_LIMBS = [4]u32{ 0, 0, 0, 256 };

fn composeWord(values: [4]M31) M31 {
    var radix = M31.one();
    var total = M31.zero();
    for (values) |limb| {
        total = total.add(limb.mul(radix));
        radix = radix.mul(M31.fromCanonical(256));
    }
    return total;
}

fn limbsOf(row: *const harness.Row, columns: [4]usize) [4]M31 {
    var out: [4]M31 = undefined;
    for (&out, columns) |*value, column| value.* = row.m31At(column);
    return out;
}

/// The honest committed `div` row of the fixture guest, read out of the witness
/// generator rather than transcribed, so a witness-generation change moves the
/// baseline instead of desynchronising it from this test.
fn honestDivRow(guest: *const harness.Guest) !harness.Row {
    try std.testing.expectEqual(@as(usize, 1), try guest.familyRowCount(.div));
    return guest.honestRow(.div, 0);
}

// Runtime: milliseconds. One eleven-instruction run and one 67-column row.
test "divisor byte range: the non-byte DIVU divisor row fails only range_check_8_8" {
    var guest = try harness.Guest.init(std.testing.allocator, divu_fixture.SPEC);
    defer guest.deinit();
    const honest = try honestDivRow(&guest);
    try harness.expectAccepted(.div, honest.slice());
    try std.testing.expectEqual(M31.fromCanonical(divu.QUOTIENT), honest.m31At(Q[0]));

    var forged = honest;
    forged.apply(nonByteDivisorForgery().values());

    // The forgery is self-consistent because it does not change the divisor's
    // field value: 256 * 2^24 = 2^32 == 2 (mod 2^31 - 1).
    try std.testing.expectEqual(
        M31.fromCanonical(divu.DIVISOR),
        composeWord(limbsOf(&forged, RS2_NEXT)),
    );
    try std.testing.expectEqual(
        composeWord(limbsOf(&honest, RS2_NEXT)),
        composeWord(limbsOf(&forged, RS2_NEXT)),
    );

    const rejection = try harness.expectOnlyLookup(.div, forged.slice(), .range_check_8_8);
    // `div` sends three pairs to `range_check_8_8`: its two divisor byte pairs
    // and its sign residual pair. Pinning the tuple names which one failed —
    // the second `divisor_ranges` request, over the divisor's high limbs.
    try std.testing.expectEqual(@as(usize, 2), rejection.tuple().len);
    try std.testing.expectEqual(forged.cells[RS2_NEXT[2]], rejection.tuple()[0]);
    try std.testing.expectEqual(forged.cells[RS2_NEXT[3]], rejection.tuple()[1]);
    try std.testing.expectEqual(
        M31.fromCanonical(256),
        rejection.tuple()[1].tryIntoM31() catch unreachable,
    );
    // The access block the failing tuple came from is the divisor's, not rs1's.
    try std.testing.expectEqual(layout.nextLimbColumn(.div, RS2_SLOT, 3), RS2_NEXT[3]);
}

// Runtime: milliseconds. Same shape as the test above.
test "divisor byte range: byte divisor limbs push the same false quotient onto the remainder bound" {
    var guest = try harness.Guest.init(std.testing.allocator, divu_fixture.SPEC);
    defer guest.deinit();
    const honest = try honestDivRow(&guest);

    var forged = honest;
    forged.apply(byteDivisorForgery().values());
    // The divisor keeps its honest byte decomposition; only the claim moves.
    try std.testing.expectEqualSlices(
        M31,
        &limbsOf(&honest, RS2_NEXT),
        &limbsOf(&forged, RS2_NEXT),
    );

    // With byte limbs the remainder bound catches the claim on its own: this is
    // the check `[0, 0, 0, 256]` evades, and therefore the reason the divisor
    // byte range is what closes the hole rather than a redundant guard.
    const rejection = try harness.expectOnlyLookup(.div, forged.slice(), .range_check_20);
    try std.testing.expectEqual(@as(usize, 1), rejection.tuple().len);
    try std.testing.expectEqual(
        M31.fromCanonical(m31.Modulus - (divu.DIVIDEND - divu.DIVISOR) - 1),
        rejection.tuple()[0].tryIntoM31() catch unreachable,
    );
}

// Runtime: milliseconds.
test "divisor byte range: the non-byte divisor also moves the memory bus, so end-to-end rejection is not attribution" {
    var guest = try harness.Guest.init(std.testing.allocator, divu_fixture.SPEC);
    defer guest.deinit();
    const honest = try honestDivRow(&guest);
    var forged = honest;
    forged.apply(nonByteDivisorForgery().values());

    // The divisor's committed limbs *are* elements of the register access
    // tuples this row offers to `memory_access`, so a non-byte limb changes
    // what the row asks that bus for, while the producing `ADDI` still emits
    // the honest bytes. The global memory argument therefore rejects this
    // forgery on its own, whatever the divisor byte range does — which is why
    // the end-to-end test below is evidence that the forged row is refused in
    // production, not evidence about which check refuses it. Attribution to the
    // two `divisor_ranges` requests lives in the row-local test above, and no
    // end-to-end forgery can supply it: every value those requests range-check
    // is also a bus tuple element.
    try std.testing.expect(
        try harness.busFingerprint(.div, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.div, forged.slice(), .memory_access),
    );
    // The claim is specific to the bus. The row's state-chain and program
    // tuples are untouched, so the difference above is the register access.
    try std.testing.expectEqual(
        try harness.busFingerprint(.div, honest.slice(), .registers_state),
        try harness.busFingerprint(.div, forged.slice(), .registers_state),
    );
    try std.testing.expectEqual(
        try harness.busFingerprint(.div, honest.slice(), .program_access),
        try harness.busFingerprint(.div, forged.slice(), .program_access),
    );
}

// Runtime: about fifty-five seconds — two proofs of an eleven-instruction
// guest, dominated by the fixed-size preprocessed lookup tables rather than by
// the guest. Bounded by construction: one committed `div` row.
test "divisor byte range: the honest DIVU proof verifies and the forged committed row does not" {
    // The honest half is the new coverage: before this test nothing in the
    // repository proved a `div` row end to end. The forged half now reaches a
    // real proof and loses at verification, which is the stage a fix living in a
    // lookup request belongs at. It is still not attribution: the test above
    // shows the same forgery moves the `memory_access` fingerprint, so the
    // global memory argument would reject this row even with `divisor_ranges`
    // deleted. Attribution lives in the row-local tests, which name the two
    // requests.
    const forgery = nonByteDivisorForgery();
    try harness.expectHonestProofAndForgedRejection(
        std.testing.allocator,
        "divisor byte-range guest (DIVU 100/2)",
        divu_fixture.SPEC,
        .{
            .target = .{ .opcode = .{ .family = .div } },
            .logical_row = 0,
            .values = forgery.values(),
        },
        .verification,
    );
}
