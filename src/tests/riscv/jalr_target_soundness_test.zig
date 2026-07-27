//! A `JALR` whose committed jump target is not the one its source register and
//! immediate determine is rejected, and rejected *by* the binding that closed
//! the hole rather than incidentally.
//!
//! The guest. Five body instructions, of which four retire: three build
//! `x6 = TARGET - 4`, then `JALR x7, 4(x6)` jumps to the epilogue's first
//! instruction, skipping the fifth. `x10 = 7` is set before the jump and the
//! skipped instruction is `ADDI x10, x0, 99`, so the published output word is
//! the guest's own evidence that control transferred. `TARGET` is 4-aligned by
//! construction: this AIR requires a 4-aligned target, deliberately stricter
//! than RV32 JALR (which clears only bit 0), because a misaligned target is
//! refused before witness construction in this profile.
//!
//! Three forgeries, and their guards are not the same check.
//!
//! Forgery A — a non-byte source byte steers the jump. `rs1.next[1] = 256` is not
//! a byte, and 256 is invertible in M31, so `composeU32(rs1.next)` grows by
//! `256 * 256 = 2^16` and the target moves from `TARGET` to `TARGET + 2^16`,
//! outside the program entirely. The row stays coherent everywhere else: the
//! forged target is 4-aligned, its four limbs are bytes, its `target / 4` split
//! is inside the bounded low20/high8 window, and the byte-carry recurrence closes
//! because the non-byte limb behaves exactly like an honest carry —
//! `(256 + 0 + 0 - 0) / 256 = 1` is a legal carry bit. Every direct constraint
//! vanishes and the only obligation left is `rs1_middle_bytes`, so that
//! `range_check_8_8` request is what refuses the row.
//!
//! Forgery B — a flipped `to_pc_lsb` redirects the target by one. The old AIR
//! constrained `2 * to_pc_over_two + to_pc_lsb = rs1 + imm` and only bit-checked
//! `to_pc_lsb`, so it admitted a second assignment: flip the bit and claim
//! `target = rs1 + imm - 1`. That claim still satisfies the new byte-carry
//! recurrence — `target + bit0` composes to the same word — which is why the
//! recurrence is *not* what rejects it. What rejects it is the bounded
//! `target / 4 = low20 + 2^20 * high8` split. Every in-range pair
//! (`low20 < 2^20`, `high8 < 2^8`) makes `4 * (low20 + 2^20 * high8)` an integer
//! multiple of four below `2^30 < p`, and the forged target is odd, so no
//! in-range pair exists: the prover must commit the field quotient
//! `target * 4^-1 mod p`, far above `2^20`, and its `range_check_20` request is
//! out of table. This is the finding the module records: for the by-one redirect
//! the guard is a lookup, not a constraint.
//!
//! Forgery C — bit 0 alone. `to_pc_lsb` reaches no relation tuple at all, so
//! flipping it and touching nothing else leaves every lookup and every bus
//! request identical to the honest row and breaks only the four carry
//! constraints. That is the sharpest statement of the fix — bit 0 is derived,
//! not prover-chosen — and it is the one forgery here whose end-to-end rejection
//! is attributable, because nothing else about the row moved.
//!
//! What the end-to-end cases do and do not show. The honest half is the load
//! bearing one: before this file nothing in the repository proved a `jalr` row at
//! all, so a rejection test alone would also be satisfied by a guest that cannot
//! be proven. The forged halves prove the forged rows are refused in production,
//! and each is pinned to the stage its own fix lives at. Forgeries A and B leave
//! every direct constraint vanishing, so they reach a real proof and lose the
//! global LogUp closure: `.verification`. Forgery C breaks the carry recurrence
//! itself, so no proof exists: `.prover_constraints`. Only C is *attributable*
//! end to end, because only C moves no relation tuple; A and B also move this
//! row's `memory_access` tuple, so the stage they reach cannot separate the range
//! check from the memory argument. Row-local attribution is where the evidence
//! for A and B lives.
//!
//! Why row overrides. A single additive cell mutation cannot express any of
//! these rows: raising `rs1_next_1` alone breaks the read-only access binding
//! (`next == previous`) and the carry chain, so the row would be rejected with
//! the byte range deleted and the test would guard nothing. See
//! `prover/test_witness_hook.zig`.
//!
//! Runtime: about two minutes for the module — four row-local cases in
//! milliseconds and four proofs of a twelve-step guest at three FRI queries,
//! each about thirty seconds and dominated by the fixed-size preprocessed lookup
//! tables rather than by the guest. Bounded by construction: one committed
//! `jalr` row.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");
const row_admissibility = @import("row_admissibility.zig");
const opcode_entries = @import("../../frontends/riscv/air/lookups/opcode_entries.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");
const jalr_air = @import("../../frontends/riscv/air/semantics/jalr.zig");

// ---------------------------------------------------------------------------
// The guest
// ---------------------------------------------------------------------------

/// Body length, needed before `BODY` exists so `TARGET` can name the epilogue's
/// entry. Checked against the assembled body below.
const BODY_LEN: usize = 5;

/// Body index of the JALR, so `bodyPc` and `bodyClock` name its committed row.
const JALR_INDEX: usize = 3;

/// The jump lands on the epilogue's first instruction. `bodyPc(BODY_LEN)` is one
/// word past the last body instruction, which is where the epilogue starts.
const TARGET: u32 = guest_elf.bodyPc(BODY_LEN);
const JALR_IMM: u32 = 4;
const RS1_VALUE: u32 = TARGET - JALR_IMM;

comptime {
    // Every guest instruction is a word address and the target is 4-aligned, so
    // the honest row satisfies the AIR's alignment bound rather than tripping it.
    std.debug.assert(TARGET % 4 == 0);
    std.debug.assert(BODY.len == BODY_LEN);
    std.debug.assert(RS1_VALUE - guest_elf.CODE_VADDR < 0x800);
}

fn lui(rd: u5, imm20: u20) u32 {
    return (@as(u32, imm20) << 12) | (@as(u32, rd) << 7) | 0x37;
}

fn addi(rd: u5, rs1: u5, imm12: u12) u32 {
    return (@as(u32, imm12) << 20) | (@as(u32, rs1) << 15) | (@as(u32, rd) << 7) | 0x13;
}

fn jalrWord(rd: u5, rs1: u5, imm12: u12) u32 {
    return (@as(u32, imm12) << 20) | (@as(u32, rs1) << 15) | (@as(u32, rd) << 7) | 0x67;
}

/// `x6` carries the computed target and `x7` the link; the fixture's prologue and
/// epilogue own `x1`, `x2`, `x4` and `x5`, and `x10` is the published word.
const BODY = [_]u32{
    addi(10, 0, PUBLISHED),
    lui(6, @intCast(guest_elf.CODE_VADDR >> 12)),
    addi(6, 6, @intCast(RS1_VALUE - guest_elf.CODE_VADDR)),
    jalrWord(7, 6, @intCast(JALR_IMM)),
    // Skipped by the jump. Its absence from the retired trace is what makes the
    // published word evidence that the target was taken.
    addi(10, 0, SKIPPED),
};

const PUBLISHED: u32 = 7;
const SKIPPED: u32 = 99;

const SPEC = harness.Spec{ .body = &BODY };

// ---------------------------------------------------------------------------
// Committed columns and entry positions
// ---------------------------------------------------------------------------

/// `jalr` opens `rd` as access slot 0 and `rs1` as slot 1.
const RS1_SLOT: usize = 1;

const PC = layout.columnOf(.jalr, "pc");
const CLOCK = layout.columnOf(.jalr, "clock");
const IMM_FELT = layout.columnOf(.jalr, "imm_felt");
const TO_PC_OVER_TWO = layout.columnOf(.jalr, "to_pc_over_two");
const TO_PC_LSB = layout.columnOf(.jalr, "to_pc_lsb");
const TARGET_WORD_LOW_20 = layout.columnOf(.jalr, "target_word_low_20");
const TARGET_WORD_HIGH_8 = layout.columnOf(.jalr, "target_word_high_8");
const TARGET_LIMBS = limbColumns("target");
const RS1_PREVIOUS = limbColumns("rs1_prev");
const RS1_NEXT = limbColumns("rs1_next");

fn limbColumns(comptime prefix: []const u8) [4]usize {
    return .{
        layout.columnOf(.jalr, prefix ++ "_0"),
        layout.columnOf(.jalr, prefix ++ "_1"),
        layout.columnOf(.jalr, prefix ++ "_2"),
        layout.columnOf(.jalr, prefix ++ "_3"),
    };
}

/// Position of a request in the row's eighteen-entry emission list. `jalr` sends
/// two pairs to `range_check_8_8` before the target block and two `range_check_20`
/// requests in total, so the domain alone does not name which obligation failed.
/// The entry count is pinned with them: a reordered or extended emission list
/// then fails loudly instead of aiming a probe at a neighbouring request.
const RS1_MIDDLE_BYTES_ENTRY: usize = 4;
const TARGET_WORD_LOW_20_ENTRY: usize = 6;
const N_JALR_ENTRIES: usize = 18;

/// First byte-carry constraint. `evaluate` emits, in order: `enabler` bit,
/// `to_pc_lsb` bit, `imm_sign` bit, the immediate decomposition, the target
/// composition against `4 * target_word`, and `to_pc_over_two`.
const FIRST_CARRY_CONSTRAINT: usize = 6;
const CARRY_MASK: u32 = 0b1111 << FIRST_CARRY_CONSTRAINT;

// ---------------------------------------------------------------------------
// Forgeries
// ---------------------------------------------------------------------------

/// The byte weight a non-byte `rs1.next[1] = 256` adds to the composed source
/// word, and therefore to the jump target.
const NON_BYTE_LIMB: u32 = 256;
const STEERED_TARGET: u32 = TARGET + NON_BYTE_LIMB * 256;

/// Absolute committed values for one forged row, bounded by the columns the
/// forgery names. Appending a column twice is a caller error the hook rejects,
/// so each recipe below writes disjoint columns.
const Forgery = struct {
    /// Widest recipe: two source limbs, four target limbs, the two split columns
    /// and `to_pc_over_two`.
    const CAPACITY: usize = 12;

    buffer: [CAPACITY]harness.ColumnValue = undefined,
    len: usize = 0,

    fn set(self: *Forgery, column: usize, value: u32) void {
        self.buffer[self.len] = .{ .column = @intCast(column), .value = value };
        self.len += 1;
    }

    fn values(self: *const Forgery) []const harness.ColumnValue {
        return self.buffer[0..self.len];
    }
};

/// Commit `target` as four bytes, as the bounded `target / 4` split, and as
/// `to_pc_over_two`, exactly as witness generation would for an aligned target.
fn claimAlignedTarget(forgery: *Forgery, target: u32) void {
    const word = target / 4;
    for (TARGET_LIMBS, byteLimbs(target)) |column, limb| forgery.set(column, limb);
    forgery.set(TARGET_WORD_LOW_20, word & ((1 << 20) - 1));
    forgery.set(TARGET_WORD_HIGH_8, word >> 20);
    forgery.set(TO_PC_OVER_TWO, 2 * word);
}

/// Forgery A: `rs1.next[1] = 256` steers the jump to `STEERED_TARGET`.
///
/// The source access is read-only, so `previous` moves with `next`; without that
/// the row fails `readOnlyAccessConstraints` and the rejection would say nothing
/// about the byte range.
fn steeredTargetForgery() Forgery {
    var forgery = Forgery{};
    forgery.set(RS1_PREVIOUS[1], NON_BYTE_LIMB);
    forgery.set(RS1_NEXT[1], NON_BYTE_LIMB);
    claimAlignedTarget(&forgery, STEERED_TARGET);
    return forgery;
}

/// Forgery B: `to_pc_lsb = 1` with `target = rs1 + imm - 1`.
///
/// The target is odd, so it has no aligned `target / 4` split. The split equation
/// `composeU32(target_limbs) = 4 * target_word` is still satisfiable in the
/// field — 4 is invertible in M31 — so the recipe commits the field quotient and
/// lets the `range_check_20` bound on `low20` be the obligation that fails.
fn byOneRedirectForgery() Forgery {
    var forgery = Forgery{};
    forgery.set(TO_PC_LSB, 1);
    for (TARGET_LIMBS, byteLimbs(TARGET - 1)) |column, limb| forgery.set(column, limb);
    forgery.set(TARGET_WORD_LOW_20, fieldQuotient(TARGET - 1, 4));
    forgery.set(TARGET_WORD_HIGH_8, 0);
    forgery.set(TO_PC_OVER_TWO, fieldQuotient(TARGET - 1, 2));
    return forgery;
}

/// Forgery C: bit 0 flipped and nothing else.
fn freeBitForgery() Forgery {
    var forgery = Forgery{};
    forgery.set(TO_PC_LSB, 1);
    return forgery;
}

fn byteLimbs(word: u32) [4]u32 {
    return .{ word & 0xff, (word >> 8) & 0xff, (word >> 16) & 0xff, word >> 24 };
}

/// `value / divisor` in M31 rather than in the integers: the representative a
/// prover would commit when the integer quotient does not exist.
fn fieldQuotient(value: u32, divisor: u32) u32 {
    return M31.fromCanonical(value)
        .mul(M31.fromCanonical(divisor).invUncheckedNonZero())
        .toU32();
}

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

/// Bitmask of the direct constraints `columns` fails, in `semantic_eval` order.
///
/// `harness.expectOnlyLookup` proves this mask is empty; a constraint-guarded
/// forgery needs the mask itself, because the carry recurrence is a chain: the
/// first bad carry feeds the next, so one lie fails all four constraints and
/// "exactly one constraint failed" is the wrong obligation to assert.
fn failingConstraints(columns: []const QM31) !u32 {
    const evaluation = try semantic_eval.evaluate(.jalr, columns, QM31.one());
    // `semantic_eval` appends the component-placement equality after the
    // family's own constraints, so the evaluated width is `N_CONSTRAINTS + 1`.
    // Pinning it here means a constraint added to `jalr.zig` without updating
    // `FIRST_CARRY_CONSTRAINT` shows up as a failed identity rather than as a
    // mask that silently names the wrong constraints.
    try std.testing.expectEqual(semantic_eval.constraintCount(.jalr), evaluation.len);
    try std.testing.expectEqual(jalr_air.N_CONSTRAINTS + 1, evaluation.len);
    var mask: u32 = 0;
    for (evaluation.values[0..evaluation.len], 0..) |value, index| {
        if (!value.isZero()) mask |= @as(u32, 1) << @intCast(index);
    }
    return mask;
}

/// The honest committed `jalr` row of the fixture guest, read out of the witness
/// generator rather than transcribed, so a witness-generation change moves the
/// baseline instead of desynchronising it from this test.
fn honestJalrRow(guest: *const harness.Guest) !harness.Row {
    try std.testing.expectEqual(@as(usize, 1), try guest.familyRowCount(.jalr));
    return guest.honestRow(.jalr, 0);
}

// ---------------------------------------------------------------------------
// Row-local attribution
// ---------------------------------------------------------------------------

// Runtime: milliseconds. One twelve-step run and one 41-column row.
test "jalr target: the honest row commits the aligned target the guest jumped to" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    // The jump was taken: the skipped `ADDI x10, x0, 99` never retired, so the
    // register the epilogue publishes still holds the pre-jump value, and the
    // link register holds the JALR's own `pc + 4`.
    try std.testing.expectEqual(PUBLISHED, guest.run.final_regs[10]);
    try std.testing.expectEqual(guest_elf.bodyPc(JALR_INDEX) + 4, guest.run.final_regs[7]);
    // Exactly one instruction of the assembled program did not retire, and the
    // register value above says which: a run that fell through the JALR would
    // retire all of them and still hold `x7 = pc + 4`.
    try std.testing.expectEqual(
        guest_elf.instructionCount(SPEC) - 1,
        guest.run.step_count,
    );

    const honest = try honestJalrRow(&guest);
    try harness.expectAccepted(.jalr, honest.slice());
    try std.testing.expectEqual(@as(u32, 0), try failingConstraints(honest.slice()));

    try std.testing.expectEqual(
        M31.fromCanonical(guest_elf.bodyPc(JALR_INDEX)),
        honest.m31At(PC),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(guest_elf.bodyClock(JALR_INDEX)),
        honest.m31At(CLOCK),
    );
    try std.testing.expectEqual(M31.fromCanonical(JALR_IMM), honest.m31At(IMM_FELT));
    try std.testing.expectEqual(
        M31.fromCanonical(RS1_VALUE),
        composeWord(limbsOf(&honest, RS1_NEXT)),
    );
    // Bit 0 of `rs1 + imm` is zero, so the honest row carries no cleared bit and
    // the target is the sum itself, committed as bytes and as `target / 4`.
    try std.testing.expectEqual(M31.zero(), honest.m31At(TO_PC_LSB));
    try std.testing.expectEqual(
        M31.fromCanonical(TARGET),
        composeWord(limbsOf(&honest, TARGET_LIMBS)),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(TARGET / 4),
        honest.m31At(TARGET_WORD_LOW_20),
    );
    try std.testing.expectEqual(M31.zero(), honest.m31At(TARGET_WORD_HIGH_8));
    try std.testing.expectEqual(M31.fromCanonical(TARGET / 2), honest.m31At(TO_PC_OVER_TWO));

    // The access-block arithmetic and the field names land on the same columns,
    // so `rs1_next_1` really is the source limb the byte range checks.
    try std.testing.expectEqual(layout.nextLimbColumn(.jalr, RS1_SLOT, 1), RS1_NEXT[1]);
    try std.testing.expectEqual(layout.previousLimbColumn(.jalr, RS1_SLOT, 1), RS1_PREVIOUS[1]);
    // The two entry positions the forgery tests pin are only meaningful for this
    // emission list.
    try std.testing.expectEqual(N_JALR_ENTRIES, opcode_entries.entryCount(.jalr));
}

// Runtime: milliseconds.
test "jalr target: a non-byte source byte steers the jump and only range_check_8_8 refuses it" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestJalrRow(&guest);

    var forged = honest;
    forged.apply(steeredTargetForgery().values());

    // The forged row is a coherent JALR to a different address: the source word
    // and the target both grew by 2^16, the target is still 4-aligned, and every
    // target-side guard still passes.
    try std.testing.expectEqual(
        M31.fromCanonical(STEERED_TARGET),
        composeWord(limbsOf(&forged, TARGET_LIMBS)),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(STEERED_TARGET - JALR_IMM),
        composeWord(limbsOf(&forged, RS1_NEXT)),
    );
    try std.testing.expect(STEERED_TARGET % 4 == 0);
    for (byteLimbs(STEERED_TARGET)) |limb| try std.testing.expect(limb < 256);
    try std.testing.expect(STEERED_TARGET / 4 < 1 << 20);

    // The only failing obligation is the source middle-byte pair. Delete that
    // request and this row is admissible.
    const rejection = try harness.expectOnlyLookup(.jalr, forged.slice(), .range_check_8_8);
    try std.testing.expectEqual(RS1_MIDDLE_BYTES_ENTRY, rejection.index);
    try std.testing.expectEqual(@as(usize, 2), rejection.tuple().len);
    try std.testing.expectEqual(
        M31.fromCanonical(NON_BYTE_LIMB),
        rejection.tuple()[0].tryIntoM31() catch unreachable,
    );
    try std.testing.expectEqual(forged.cells[RS1_NEXT[2]], rejection.tuple()[1]);

    // The steered source limbs are elements of the register access tuples this
    // row offers to `memory_access`, so the global memory argument rejects the
    // row on its own. That is why the end-to-end case below proves reachability
    // rather than attribution.
    try std.testing.expect(
        try harness.busFingerprint(.jalr, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.jalr, forged.slice(), .memory_access),
    );
}

// Runtime: milliseconds.
test "jalr target: the by-one redirect satisfies the carry recurrence and fails the bounded split" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestJalrRow(&guest);

    var forged = honest;
    forged.apply(byOneRedirectForgery().values());

    // The recurrence's own statement still holds: `target + bit0` composes to
    // `rs1 + imm`, which is why the four carry constraints vanish and the
    // recurrence is not this forgery's guard.
    try std.testing.expectEqual(
        composeWord(limbsOf(&honest, RS1_NEXT)).add(M31.fromCanonical(JALR_IMM)),
        composeWord(limbsOf(&forged, TARGET_LIMBS)).add(forged.m31At(TO_PC_LSB)),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(TARGET - 1),
        composeWord(limbsOf(&forged, TARGET_LIMBS)),
    );

    // The odd target has no integer `target / 4`, so the split holds only with a
    // `low20` far above the 2^20 table bound. That request is the obligation
    // that fails; delete it and this row is admissible.
    const rejection = try harness.expectOnlyLookup(.jalr, forged.slice(), .range_check_20);
    try std.testing.expectEqual(TARGET_WORD_LOW_20_ENTRY, rejection.index);
    try std.testing.expectEqual(@as(usize, 1), rejection.tuple().len);
    const claimed_low_20 = rejection.tuple()[0].tryIntoM31() catch unreachable;
    try std.testing.expectEqual(M31.fromCanonical(fieldQuotient(TARGET - 1, 4)), claimed_low_20);
    try std.testing.expect(claimed_low_20.toU32() >= 1 << 20);

    // The redirect moves the emitted next-pc and nothing on the register bus,
    // which is the shape of a target-only lie.
    try std.testing.expect(
        try harness.busFingerprint(.jalr, honest.slice(), .registers_state) !=
            try harness.busFingerprint(.jalr, forged.slice(), .registers_state),
    );
    try std.testing.expectEqual(
        try harness.busFingerprint(.jalr, honest.slice(), .memory_access),
        try harness.busFingerprint(.jalr, forged.slice(), .memory_access),
    );
}

// Runtime: milliseconds.
test "jalr target: bit 0 is derived, so flipping it alone fails only the carry recurrence" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestJalrRow(&guest);

    var forged = honest;
    forged.apply(freeBitForgery().values());

    // `to_pc_lsb` reaches no relation tuple, so every lookup and every bus
    // request is byte-identical to the honest row. Nothing but the recurrence
    // can object, and the recurrence objects: bit 0 is derived from the source
    // bytes and the immediate, not chosen.
    try std.testing.expectEqual(
        try row_admissibility.fingerprint(.jalr, honest.slice()),
        try row_admissibility.fingerprint(.jalr, forged.slice()),
    );
    try std.testing.expectEqual(CARRY_MASK, try failingConstraints(forged.slice()));
    switch (try harness.attribute(.jalr, forged.slice())) {
        .constraints => |failure| {
            try std.testing.expectEqual(FIRST_CARRY_CONSTRAINT, failure.index);
            try std.testing.expectEqual(@as(usize, 4), failure.count);
        },
        else => return error.TestUnexpectedResult,
    }
}

// ---------------------------------------------------------------------------
// End-to-end committed trace
// ---------------------------------------------------------------------------

// Runtime: about thirty seconds — one proof of a twelve-step guest, dominated by
// the fixed-size preprocessed lookup tables rather than by the guest. Bounded by
// construction: one committed `jalr` row.
test "jalr target: the honest JALR guest proves and verifies" {
    // This is the new coverage. Before this file nothing in the repository
    // proved a `jalr` row end to end, so each rejection below would otherwise
    // also be satisfied by a guest that cannot be proven at all.
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try guest.proveAndVerify();
}

// Runtime: about thirty seconds — one proof.
test "jalr target: the committed steered-target row is refused in production" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const forgery = steeredTargetForgery();
    // Refused at verification, not at proving: every direct constraint of the
    // forged row vanishes, so a proof exists and the global LogUp closure is
    // what refuses it. The non-byte source limb has no `range_check_8_8` row to
    // cancel against, and the same override also moves this row's
    // `memory_access` tuple, so the stage says which half of the pipeline
    // rejects and not which of those two relations did it — see the header.
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = .jalr } },
        .logical_row = 0,
        .values = forgery.values(),
    } }, .verification);
}

// Runtime: about thirty seconds — one proof.
test "jalr target: the committed by-one redirect is refused in production" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const forgery = byOneRedirectForgery();
    // Same shape as the steered target: the carry recurrence closes on the
    // redirected address, so the row proves and the out-of-range `range_check_20`
    // request on the bounded target split is missing from the global sum.
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = .jalr } },
        .logical_row = 0,
        .values = forgery.values(),
    } }, .verification);
}

// Runtime: about thirty seconds — one proof.
test "jalr target: the committed flipped bit 0 is refused by the carry recurrence in production" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const forgery = freeBitForgery();
    // The attributable end-to-end case: this override moves no relation tuple,
    // so the LogUp constraints still vanish and the only thing that can stop the
    // proof is the byte-carry recurrence. Delete those four constraints and this
    // proof is produced *and verifies*.
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = .jalr } },
        .logical_row = 0,
        .values = forgery.values(),
    } }, .prover_constraints);
}
