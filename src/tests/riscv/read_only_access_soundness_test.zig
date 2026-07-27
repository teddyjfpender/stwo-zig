//! A read-only register access must emit the value it consumed, and a `BEQ` row
//! that emits a different value is rejected *by* that binding.
//!
//! The bug this guards. A committed access carries `previous` and `next` as two
//! distinct column groups: the access chain consumes `previous` at
//! `previous_clock` and emits `next` at its derived ordered access clock, and
//! the opcode semantics compute on `next`. Nothing tied the two for a source
//! operand, so `next` was a
//! free prover choice that was *also* what the row wrote back into the register
//! cell. Every register-reading instruction therefore doubled as an arbitrary
//! register write. `common.readOnlyAccessConstraints` closes it by forcing
//! `next == previous` limbwise on every read-only access of all sixteen
//! register-touching families.
//!
//! Why `BEQ` is the vehicle. A branch writes no register at all —
//! `committed_row_layout.writtenSlot(.branch_eq)` is null, so *both* of its
//! accesses are read-only and neither `next` group is pinned by a destination
//! result. It is the cleanest possible demonstration: with the binding deleted a
//! `BEQ` still branches correctly and simultaneously stores a chosen word into
//! two registers.
//!
//! The two forgeries. The first is the confirmed exploit: the row consumes
//! `0xdeadb000` and emits `0x7f7f7f7f`. The second emits the non-byte limb
//! `1000000`. `branch_eq` byte-ranges nothing — its register limbs reach only
//! the `memory_access` bus — so row-locally a non-byte limb is admissible the
//! moment `next == previous` holds. That is the point: byte-ness of a register
//! value on that bus is *inductive*, supplied by the producing family that
//! byte-ranged its write, and the read-only binding is what stops a consuming
//! family from injecting a fresh non-byte word into the chain. The `div`
//! `lt_diff` bound and every other argument that assumes a consumed limb is a
//! byte rests on it.
//!
//! Both forgeries move the emitted limbs of *both* accesses, not just the one
//! register the exploit named. `BEQ`'s equality constraint compares the two
//! `next` groups limbwise, so a coherent forgery must move them together — which
//! makes the hole worse rather than harder to reach: one `BEQ` writes two
//! arbitrary words. Nothing else in either forged row moves.
//!
//! Attribution is row-local, and can only be row-local. Each row-local test
//! pins the failing constraint index and count through `harness.attribute` —
//! whose `.constraints` verdict already says a direct constraint and not a
//! preprocessed table rejected the row — and then shows the *counterfactual*:
//! re-applying the forged word to `previous` as well makes the row admissible
//! again, so the rejection is the read-only binding and not a sibling
//! constraint that happened to catch it.
//!
//! What the end-to-end test does and does not show. It proves that an honest
//! `branch_eq` row can be committed and proven at all — nothing in the
//! repository showed that before — and that both forged rows are refused in
//! production before a proof exists, which is the stage a direct-constraint fix
//! belongs at. It still cannot attribute that refusal to the read-only binding
//! specifically: every column that binding constrains is a `memory_access` tuple
//! element — `next` is the emitted tuple, `previous` the consumed one — so the
//! global memory argument would also reject these rows. The control test states
//! the scope of that as an executable fact rather than a caveat: an override of
//! `rs1_clock_prev`, which reaches no direct constraint of the family, is
//! row-locally admissible, does produce a proof, and is refused by the global
//! closure alone. So the two stages now separate a constraint fix from a bus
//! fix, and only the row-local tests separate this binding from the bus.
//!
//! Why a row override is required. A single additive mutation of `rs1_next_0`
//! also breaks the `BEQ` equality constraint, because `rs2_next_0` no longer
//! matches. That row is rejected whether or not the read-only binding exists, so
//! such a test would pass with the fix deleted and guard nothing.
//!
//! Runtime: milliseconds for the three row-local tests; about half a minute for
//! the control test; about a minute and a half for the end-to-end test, which
//! proves a thirteen-instruction guest once honestly and then twice more up to
//! the prover's constraint check.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;

const access_clock = @import("../../frontends/riscv/access_clock.zig");
const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");

// ---------------------------------------------------------------------------
// The guest
// ---------------------------------------------------------------------------

/// `LUI x3, 0xdeadb`, `LUI x6, 0xdeadb`, `BEQ x3, x6, 4`.
///
/// Two equal registers make the branch taken: `cmp_result` is not a prover
/// choice, because with equal `next` limbs the marker constraint
/// `enabler * (1 - diff_inv_sum)` can only close at `cmp_result = 1`. The taken
/// target is `pc + 4`, so the body stays straight-line and `guest_elf.bodyRow`
/// keeps describing it. `x3` and `x6` avoid the prologue/epilogue registers
/// `x1`, `x2`, `x4`, `x5`.
const BODY = [_]u32{ 0xdead_b1b7, 0xdead_b337, 0x0061_8263 };

/// The consumed register word, published so the statement carries the value the
/// forgeries contradict.
const HONEST_WORD: u32 = 0xdead_b000;
const RS1_REG: u5 = 3;
const RS2_REG: u5 = 6;

const SPEC = guest_elf.Spec{ .body = &BODY, .publish = RS1_REG };

/// The word the confirmed exploit emitted in place of the consumed one.
const FORGED_WORD: u32 = 0x7f7f_7f7f;

/// A limb no byte range would admit, and the value the original exploit was also
/// observed to accept.
const NON_BYTE_LIMB: u32 = 1_000_000;

fn limbsOf(word: u32) [4]u32 {
    return .{
        word & 0xff,
        (word >> 8) & 0xff,
        (word >> 16) & 0xff,
        word >> 24,
    };
}

// ---------------------------------------------------------------------------
// Committed columns and constraint indices
// ---------------------------------------------------------------------------

// Named through the committed layout so a reordered or renamed access column is
// a compile error rather than a probe landing on its neighbour.
const RS1_ADDR = layout.columnOf(.branch_eq, "rs1_addr");
const RS2_ADDR = layout.columnOf(.branch_eq, "rs2_addr");
const ROW_CLOCK = layout.columnOf(.branch_eq, "clock");
const RS1_CLOCK_PREV = layout.columnOf(.branch_eq, "rs1_clock_prev");
const RS2_CLOCK_PREV = layout.columnOf(.branch_eq, "rs2_clock_prev");
const CMP_RESULT = layout.columnOf(.branch_eq, "cmp_result");
const RS1_PREVIOUS = limbColumns("rs1_prev");
const RS1_NEXT = limbColumns("rs1_next");
const RS2_PREVIOUS = limbColumns("rs2_prev");
const RS2_NEXT = limbColumns("rs2_next");

fn limbColumns(comptime prefix: []const u8) [4]usize {
    return .{
        layout.columnOf(.branch_eq, prefix ++ "_0"),
        layout.columnOf(.branch_eq, prefix ++ "_1"),
        layout.columnOf(.branch_eq, prefix ++ "_2"),
        layout.columnOf(.branch_eq, prefix ++ "_3"),
    };
}

/// One read-only residual per limb of each of the two accesses.
const N_READ_ONLY: usize = 8;

/// `semantic_eval` appends the placement equality after the family's own
/// constraints, and `branch_eq.evaluate` emits the read-only block last: `rs1`
/// limbs 0..3 then `rs2` limbs 0..3. Both facts are verified below by probing
/// each residual on its own rather than trusted.
const READ_ONLY_BASE: usize =
    semantic_eval.constraintCount(.branch_eq) - 1 - N_READ_ONLY;

fn readOnlyConstraint(slot: usize, limb: usize) usize {
    return READ_ONLY_BASE + slot * 4 + limb;
}

// ---------------------------------------------------------------------------
// The forgeries
// ---------------------------------------------------------------------------

/// Absolute committed values for one forged row. Bounded by the columns a
/// read-only forgery can name: the emitted and consumed limbs of two accesses.
const Forgery = struct {
    const CAPACITY: usize = 16;

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

/// Emit `0x7f7f7f7f` from both sources while consuming the honest word: the
/// exploit that turns a `BEQ` into two arbitrary register writes. The branch
/// itself still decides correctly, because equality holds over the forged limbs.
fn writeBackForgery() Forgery {
    var forgery = Forgery{};
    forgery.setLimbs(RS1_NEXT, limbsOf(FORGED_WORD));
    forgery.setLimbs(RS2_NEXT, limbsOf(FORGED_WORD));
    return forgery;
}

/// Emit a non-byte low limb from both sources. Only limb 0 moves, so the
/// rejection cannot be blamed on any other limb's residual.
fn nonByteForgery() Forgery {
    var forgery = Forgery{};
    forgery.set(RS1_NEXT[0], NON_BYTE_LIMB);
    forgery.set(RS2_NEXT[0], NON_BYTE_LIMB);
    return forgery;
}

/// The same forged words consumed as well as emitted.
///
/// This is the counterfactual each attribution rests on: the row is otherwise
/// identical to the forgery, so if it is admissible then the forgery's rejection
/// is exactly `next != previous` and nothing else. It also states what the
/// binding does *not* do — a non-byte limb is row-locally fine once it is
/// consumed rather than invented, because `branch_eq` byte-ranges nothing.
fn writeBackWithMatchingConsume() Forgery {
    var forgery = writeBackForgery();
    forgery.setLimbs(RS1_PREVIOUS, limbsOf(FORGED_WORD));
    forgery.setLimbs(RS2_PREVIOUS, limbsOf(FORGED_WORD));
    return forgery;
}

fn nonByteWithMatchingConsume() Forgery {
    var forgery = nonByteForgery();
    forgery.set(RS1_PREVIOUS[0], NON_BYTE_LIMB);
    forgery.set(RS2_PREVIOUS[0], NON_BYTE_LIMB);
    return forgery;
}

const BRANCH_EQ_TARGET: harness.Target = .{ .opcode = .{ .family = .branch_eq } };

fn override(forgery: *const Forgery) harness.RowOverride {
    return .{ .target = BRANCH_EQ_TARGET, .logical_row = 0, .values = forgery.values() };
}

/// The honest committed `branch_eq` row of the fixture guest, read out of the
/// witness generator rather than transcribed.
fn honestBranchRow(guest: *const harness.Guest) !harness.Row {
    try std.testing.expectEqual(@as(usize, 1), try guest.familyRowCount(.branch_eq));
    return guest.honestRow(.branch_eq, 0);
}

fn composeWord(row: *const harness.Row, columns: [4]usize) u32 {
    var value: u32 = 0;
    var shift: u5 = 0;
    for (columns) |column| {
        value |= row.m31At(column).toU32() << shift;
        shift +%= 8;
    }
    return value;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Runtime: milliseconds. One thirteen-instruction run and one 30-column row.
test "read-only access: each residual of the branch_eq read-only block is a constraint of its own" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestBranchRow(&guest);
    try harness.expectAccepted(.branch_eq, honest.slice());

    // A branch writes no register, so both accesses are read-only and neither
    // `next` group is pinned by a destination result.
    try std.testing.expect(layout.writtenSlot(.branch_eq) == null);

    // The guest's own facts, so a fixture change that stops exercising the
    // taken-branch case fails here rather than silently weakening the forgeries.
    try std.testing.expectEqual(M31.fromCanonical(RS1_REG), honest.m31At(RS1_ADDR));
    try std.testing.expectEqual(M31.fromCanonical(RS2_REG), honest.m31At(RS2_ADDR));
    try std.testing.expectEqual(M31.one(), honest.m31At(CMP_RESULT));
    try std.testing.expectEqual(HONEST_WORD, composeWord(&honest, RS1_NEXT));
    try std.testing.expectEqual(HONEST_WORD, composeWord(&honest, RS1_PREVIOUS));
    try std.testing.expectEqual(HONEST_WORD, composeWord(&honest, RS2_NEXT));

    // `READ_ONLY_BASE` and the `rs1`-then-`rs2` limb order are derived from
    // `constraintCount`, which is not evidence. `previous` reaches no other
    // direct constraint of the family, so moving one consumed limb must fail
    // exactly one constraint — and which one it is locates the whole block.
    const sentinel: u32 = 0x33;
    for ([_][4]usize{ RS1_PREVIOUS, RS2_PREVIOUS }, 0..) |columns, slot| {
        for (columns, 0..) |column, limb| {
            try std.testing.expect(honest.m31At(column).toU32() != sentinel);
            var probed = honest;
            probed.apply(&.{.{ .column = @intCast(column), .value = sentinel }});
            try harness.expectOnlyConstraint(
                .branch_eq,
                probed.slice(),
                readOnlyConstraint(slot, limb),
            );
        }
    }
}

// Runtime: milliseconds.
test "read-only access: a BEQ that emits a word it did not consume fails only the read-only residuals" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestBranchRow(&guest);

    var forged = honest;
    forged.apply(writeBackForgery().values());

    // The row still consumes the honest word and now emits another one, in both
    // registers: that is the arbitrary write.
    try std.testing.expectEqual(HONEST_WORD, composeWord(&forged, RS1_PREVIOUS));
    try std.testing.expectEqual(FORGED_WORD, composeWord(&forged, RS1_NEXT));
    try std.testing.expectEqual(FORGED_WORD, composeWord(&forged, RS2_NEXT));

    // A direct constraint rejects it, not a preprocessed table: `attribute`'s
    // `.constraints` arm is reached only when `semantic_eval` leaves a residual.
    // All four limbs of the emitted word differ from the consumed one, so all
    // eight residuals fail and the first is `rs1` limb 0.
    switch (try harness.attribute(.branch_eq, forged.slice())) {
        .constraints => |failure| {
            try std.testing.expectEqual(readOnlyConstraint(0, 0), failure.index);
            try std.testing.expectEqual(N_READ_ONLY, failure.count);
        },
        else => return error.TestUnexpectedResult,
    }

    // The counterfactual: consuming the same word makes the row admissible, so
    // the eight failures above are the read-only binding alone. The comparison,
    // the inverse markers, the taken-branch selector and the placement equality
    // are all indifferent to which word a `BEQ` reads.
    var coherent = honest;
    coherent.apply(writeBackWithMatchingConsume().values());
    try harness.expectAccepted(.branch_eq, coherent.slice());

    // The forged word reaches the register bus, which is what makes this a
    // write rather than a miscomputation: the emitted `memory_access` tuple is
    // the register's new value. The row's state chain and program tuple are
    // untouched, so the moved fingerprint is the register access.
    try std.testing.expect(
        try harness.busFingerprint(.branch_eq, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.branch_eq, forged.slice(), .memory_access),
    );
    try std.testing.expectEqual(
        try harness.busFingerprint(.branch_eq, honest.slice(), .registers_state),
        try harness.busFingerprint(.branch_eq, forged.slice(), .registers_state),
    );
    try std.testing.expectEqual(
        try harness.busFingerprint(.branch_eq, honest.slice(), .program_access),
        try harness.busFingerprint(.branch_eq, forged.slice(), .program_access),
    );
}

// Runtime: milliseconds.
test "read-only access: a non-byte limb injected onto the register bus fails only the low residuals" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestBranchRow(&guest);

    var forged = honest;
    forged.apply(nonByteForgery().values());
    try std.testing.expectEqual(
        M31.fromCanonical(NON_BYTE_LIMB),
        forged.m31At(RS1_NEXT[0]),
    );

    // Only limb 0 moved, so exactly the two limb-0 residuals fail — and a
    // `.constraints` verdict says a direct constraint rejected the row, not a
    // preprocessed table.
    switch (try harness.attribute(.branch_eq, forged.slice())) {
        .constraints => |failure| {
            try std.testing.expectEqual(readOnlyConstraint(0, 0), failure.index);
            try std.testing.expectEqual(@as(usize, 2), failure.count);
        },
        else => return error.TestUnexpectedResult,
    }

    // Consuming the same non-byte limb is row-locally admissible: `branch_eq`
    // requests no byte range over its register limbs, and the row-local oracle
    // deliberately does not decide the `memory_access` bus. So byte-ness here is
    // inductive — the read-only binding is the whole of what keeps a consuming
    // family from inventing a non-byte register word.
    var coherent = honest;
    coherent.apply(nonByteWithMatchingConsume().values());
    try harness.expectAccepted(.branch_eq, coherent.slice());

    // The non-byte limb does reach the bus, so the inductive argument would
    // otherwise have to be carried by the global memory argument alone.
    try std.testing.expect(
        try harness.busFingerprint(.branch_eq, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.branch_eq, forged.slice(), .memory_access),
    );
}

// Runtime: about half a minute. One aborted proof of the same guest.
test "read-only access: a row-locally admissible bus-moving override proves and loses the memory argument" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestBranchRow(&guest);

    // `rs1_clock_prev` reaches no direct constraint of `branch_eq`. It appears
    // only in the consumed `memory_access` tuple and in the `range_check_20`
    // request over `current_access_clock - previous_clock - 1`, which an
    // earlier clock keeps in range. So this row is row-locally admissible while
    // still asking the register bus for something else.
    const honest_previous_clock = honest.m31At(RS1_CLOCK_PREV).toU32();
    try std.testing.expect(honest_previous_clock > 1);
    const control = [_]harness.ColumnValue{.{
        .column = @intCast(RS1_CLOCK_PREV),
        .value = honest_previous_clock - 1,
    }};
    var moved = honest;
    moved.apply(&control);
    try harness.expectAccepted(.branch_eq, moved.slice());
    try std.testing.expect(
        try harness.busFingerprint(.branch_eq, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.branch_eq, moved.slice(), .memory_access),
    );

    // So proving succeeds and the global memory argument is the only thing left
    // to refuse it: `.verification`. That is what bounds the end-to-end test
    // below. Every column the read-only binding constrains is also a
    // `memory_access` tuple element, so a forgery of that binding moves this bus
    // too, and no end-to-end override can attribute a rejection to the binding
    // rather than to the bus. Attribution is the row-local tests above.
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = BRANCH_EQ_TARGET,
        .logical_row = 0,
        .values = &control,
    } }, .verification);
}

// Runtime: about half a minute. This is the exact protocol-level regression
// for the former zero-length access edge, not just a tracker-unit test.
test "strict access clocks: a same-clock source self-loop loses the shifted gap lookup" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestBranchRow(&guest);

    const instruction_clock = honest.m31At(ROW_CLOCK).toU32();
    const second_access_clock = access_clock.encode(instruction_clock, .second);
    try std.testing.expect(honest.m31At(RS2_CLOCK_PREV).toU32() < second_access_clock);

    const values = [_]harness.ColumnValue{.{
        .column = @intCast(RS2_CLOCK_PREV),
        .value = second_access_clock,
    }};
    var self_loop = honest;
    self_loop.apply(&values);

    // The consumed and emitted register tuple is now identical. All direct
    // constraints still vanish, but current - previous - 1 is p - 1, outside
    // range_check_20. Request 6 is the second source's gap in branch_eq.
    const rejection = try harness.expectOnlyLookup(
        .branch_eq,
        self_loop.slice(),
        .range_check_20,
    );
    try std.testing.expectEqual(@as(usize, 6), rejection.index);
    try std.testing.expectEqual(
        m31.Modulus - 1,
        (try rejection.tuple()[0].tryIntoM31()).toU32(),
    );

    try guest.expectRejectedAt(.{ .main_row = .{
        .target = BRANCH_EQ_TARGET,
        .logical_row = 0,
        .values = &values,
    } }, .verification);
}

// Runtime: about a minute and a half. One honest proof of a thirteen-instruction
// guest, dominated by the fixed-size preprocessed lookup tables, plus two runs
// that stop at the prover's constraint check. Bounded by construction: one
// committed `branch_eq` row.
test "read-only access: the honest BEQ proof verifies and neither forged write-back can be proven" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    // The forged rows are refused before a proof exists, which is the stage a
    // direct-constraint fix lives at and which the control test above shows a
    // merely bus-moving override does *not* reach. It is still not attribution
    // to the read-only binding: these rows also move the register bus, so a
    // second check would have caught them at the later stage.
    const write_back = writeBackForgery();
    try guest.expectRejectedAt(.{ .main_row = override(&write_back) }, .prover_constraints);

    const non_byte = nonByteForgery();
    try guest.expectRejectedAt(.{ .main_row = override(&non_byte) }, .prover_constraints);

    // The honest half is the other new coverage: before this test nothing in
    // the repository proved a `branch_eq` row end to end, and without it "the
    // forgery is rejected" would also hold for a guest that cannot be proven
    // at all. Last because its tail is the Sail agreement check, whose visible
    // skip on an absent oracle must not cost the two rejections.
    try guest.proveAndVerify("read-only access guest (BEQ on equal LUIs)");
}
