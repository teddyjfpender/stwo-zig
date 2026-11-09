//! A bitwise R-type row may not choose its own result: nothing in the direct
//! constraints computes `XOR`, `OR` or `AND`, so the whole binding is one
//! `bitwise` table request per limb.
//!
//! What `base_alu_reg` actually constrains. Its direct constraints
//! are five opcode-flag bits and an activation bit, an ADD byte-carry chain
//! gated by `is_add`, a SUB chain gated by `is_sub`, and the destination block.
//! Both sources use compact read blocks: their emitted bus values alias their
//! consumed limbs structurally, so there is no duplicate `next` group to bind.
//! On a bitwise row both carry chains are switched off, so `result` reaches
//! *no* direct constraint at all. The
//! only obligations left on it are two `range_check_8_8` pairs, which say the
//! limbs are bytes and nothing more, and the four `bitwise` requests
//! `{rs1.value[i], rs2.value[i], result[i], operation_id}`, whose table holds a
//! row only where `result[i]` is the operation applied to the two operands.
//! Take the requests away and a bitwise instruction writes an arbitrary word.
//!
//! Why the destination is `x0`. `destinationResultConstraints` pins
//! `rd.next = rd_nonzero * result`, so on any ordinary row a forged `result`
//! must move `rd.next` too — and `rd.next` is an element of the `memory_access`
//! tuple, so the register bus moves with it and the global memory argument
//! rejects the row whatever the table does. With `rd = x0`, `rd_nonzero` is
//! zero, the destination block reads `rd.next = 0` independently of `result`,
//! and `result` is left with no constraint and no bus. `XOR x0, x5, x6` is a
//! legal RV32I instruction that retires an ordinary `base_alu_reg` row.
//!
//! That is what makes this the sweep's first end-to-end forgery whose rejection
//! is attributable. The row-local test asserts it directly: all three bus
//! fingerprints — `memory_access`, `registers_state`, `program_access` — are
//! bit-identical between the honest and the forged row, so nothing global can
//! tell them apart and the only relation the forgery moves is one `bitwise`
//! request that leaves its table.
//!
//! The forgery. `XOR x0, x5, x6` with `x5` the public input word and `x6 = 15`
//! honestly commits `result[0] = 0x0e`. The prover claims `0x0d` instead: still
//! a byte, so both `range_check_8_8` pairs stay in their table, and the row asks
//! the bitwise table for `{0x01, 0x0f, 0x0d, xor}`, which does not exist.
//!
//! Stage. Every direct constraint vanishes, so proving must succeed and
//! verification must fail: the dropped request's opcode-side fraction has
//! nothing to cancel against and the global LogUp sum is non-zero. See
//! `air/lookups/tables/source_ingest.zig`'s `UnrepresentableRequest` for why the
//! harness models the adversary that omits the impossible multiplicity rather
//! than the one that aborts its own prover.
//!
//! Adversarial self-check, executed 2026-07-27. `base_alu_reg.bitwiseLookupEnabler`
//! was made to return zero, switching every bitwise request off, and this module was
//! re-run. Real output:
//!
//!   4/14 ... the honest XOR row discards its result and is admissible...OK
//!   5/14 ... the forged result fails only the bitwise table and moves no bus...
//!        expected a bitwise rejection; the row is admissible
//!   6/14 ... the forged XOR result proves and loses at verification...FAIL
//!   11/14 base_alu_reg.test.x0 discards arithmetic and bitwise results...FAIL
//!   11 passed; 0 skipped; 3 failed.
//!
//! Both halves fail, which is what makes each a guard rather than coverage: without
//! the requests the forged row is admissible *and* its proof verifies. The AIR file
//! was then restored byte-for-byte (`git diff` empty) and the module re-run green.
//!
//! Runtime: two row-local cases in milliseconds; one end-to-end case at about a
//! minute, being one honest proof and verification of a ten-instruction guest
//! plus one forged proof and verification. Bounded by construction: one
//! committed `base_alu_reg` row.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;

const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");

/// The operand the fixture's prologue loads into `x5`, read from the fixture
/// rather than transcribed.
const OPERAND: u32 = std.mem.readInt(u32, &guest_elf.INPUT, .little);
/// The second operand, and the immediate the body's `ADDI` materialises.
const MASK: u32 = 15;
const HONEST_LIMB: u32 = (OPERAND ^ MASK) & 0xff;
/// Any other byte: the claim is false, and staying a byte is what keeps the two
/// `range_check_8_8` pairs inside their table so the bitwise request is the only
/// obligation the row breaks.
const FORGED_LIMB: u32 = HONEST_LIMB ^ 1;

/// Upstream `bitwise` operation ids: 0 AND, 1 OR, 2 XOR.
const XOR_OPERATION: u32 = 2;

comptime {
    std.debug.assert(FORGED_LIMB != HONEST_LIMB);
    std.debug.assert(FORGED_LIMB < 256);
}

/// `ADDI x6, x0, 15`, `XOR x0, x5, x6`.
///
/// The prologue and epilogue own `x1`, `x2`, `x4` and `x5`, so `x6` is free;
/// the epilogue publishes it, since the instruction under test deliberately
/// writes nowhere.
const BODY = [_]u32{ 0x00F0_0313, 0x0062_C033 };
const SPEC = harness.Spec{ .body = &BODY, .publish = 6 };

const TARGET: harness.Target = .{ .opcode = .{ .family = .base_alu_reg } };

// Named through the committed layout, so a reordered or renamed column is a
// compile error rather than a probe that lands on its neighbour.
const RESULT_0 = layout.columnOf(.base_alu_reg, "result_0");
const RD_ADDR = layout.columnOf(.base_alu_reg, "rd_addr");
const RD_NONZERO = layout.columnOf(.base_alu_reg, "rd_nonzero");
const RS1_VALUE_0 = layout.nextLimbColumn(.base_alu_reg, 1, 0);
const RS2_VALUE_0 = layout.nextLimbColumn(.base_alu_reg, 2, 0);
const IS_XOR = layout.columnOf(.base_alu_reg, "opcode_xor_flag");

const FORGERY = [_]harness.ColumnValue{.{ .column = RESULT_0, .value = FORGED_LIMB }};

const OVERRIDE = harness.RowOverride{
    .target = TARGET,
    .logical_row = 0,
    .values = &FORGERY,
};

/// The one honest committed `base_alu_reg` row, read out of the witness
/// generator rather than transcribed.
fn honestRow(guest: *const harness.Guest) !harness.Row {
    try std.testing.expectEqual(@as(usize, 1), try guest.familyRowCount(.base_alu_reg));
    return guest.honestRow(.base_alu_reg, 0);
}

// Runtime: milliseconds. One ten-instruction run and one 35-column row.
test "bitwise result: the honest XOR row discards its result and is admissible" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestRow(&guest);

    try harness.expectAccepted(.base_alu_reg, honest.slice());
    try std.testing.expectEqual(M31.one(), honest.m31At(IS_XOR));
    try std.testing.expectEqual(M31.fromCanonical(OPERAND & 0xff), honest.m31At(RS1_VALUE_0));
    try std.testing.expectEqual(M31.fromCanonical(MASK), honest.m31At(RS2_VALUE_0));
    try std.testing.expectEqual(M31.fromCanonical(HONEST_LIMB), honest.m31At(RESULT_0));

    // The premise the whole file rests on: the destination is `x0`, so the
    // destination block reads `rd.next = 0` whatever `result` is, and every
    // written limb stays zero under the forgery below.
    try std.testing.expectEqual(M31.zero(), honest.m31At(RD_ADDR));
    try std.testing.expectEqual(M31.zero(), honest.m31At(RD_NONZERO));
    for (0..4) |limb| {
        try std.testing.expectEqual(
            M31.zero(),
            honest.m31At(layout.nextLimbColumn(.base_alu_reg, 0, limb)),
        );
    }
}

// Runtime: milliseconds. Same shape as the test above.
test "bitwise result: the forged result fails only the bitwise table and moves no bus" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestRow(&guest);
    var forged = honest;
    forged.apply(&FORGERY);

    // Every direct constraint vanishes — that is what `expectOnlyLookup`
    // asserts before it looks at any table — so the rejection is not a carry
    // chain, a compact-source alias or a destination write in disguise. Both
    // carry chains are gated off by `is_add` and `is_sub`, which is why
    // `result` reaches no direct constraint on a bitwise row.
    const rejection = try harness.expectOnlyLookup(.base_alu_reg, forged.slice(), .bitwise);
    try std.testing.expectEqual(@as(usize, 4), rejection.tuple().len);
    const tuple = rejection.tuple();
    try std.testing.expectEqual(
        M31.fromCanonical(OPERAND & 0xff),
        tuple[0].tryIntoM31() catch unreachable,
    );
    try std.testing.expectEqual(M31.fromCanonical(MASK), tuple[1].tryIntoM31() catch unreachable);
    try std.testing.expectEqual(
        M31.fromCanonical(FORGED_LIMB),
        tuple[2].tryIntoM31() catch unreachable,
    );
    try std.testing.expectEqual(
        M31.fromCanonical(XOR_OPERATION),
        tuple[3].tryIntoM31() catch unreachable,
    );

    // And nothing global can see the difference. This is the claim that makes
    // the end-to-end stage below attribution rather than reachability: with
    // every bus fingerprint fixed, the bitwise table is the only relation left
    // that can reject the row.
    for ([_]harness.Domain{ .memory_access, .registers_state, .program_access }) |domain| {
        try std.testing.expectEqual(
            try harness.busFingerprint(.base_alu_reg, honest.slice(), domain),
            try harness.busFingerprint(.base_alu_reg, forged.slice(), domain),
        );
    }
}

// Runtime: about a minute. One honest proof and verification of a
// ten-instruction guest, then one forged proof and verification.
test "bitwise result end-to-end: the forged XOR result proves and loses at verification" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    try std.testing.expectEqual(MASK, guest.run.final_regs[6]);
    // `XOR x0, ...` wrote nowhere, which is the property the forgery exploits.
    try std.testing.expectEqual(@as(u32, 0), guest.run.final_regs[0]);

    // `.verification`, not `.prover_constraints`: the forged row satisfies every
    // direct constraint, so a proof exists and it is the global LogUp closure
    // that refuses it. Pinning the stage is what distinguishes this fix from a
    // constraint fix — delete the bitwise requests and the proof verifies.
    try guest.expectRejectedAt(.{ .main_row = OVERRIDE }, .verification);

    // Without this the rejection above would also be satisfied by a guest that
    // cannot be proven at all. Last because its tail is the Sail agreement
    // check, whose visible skip on an absent oracle must not cost the
    // rejection half.
    try guest.proveAndVerify("bitwise result guest (XOR into x6 and x0)");
}
