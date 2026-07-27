//! An `AUIPC` immediate carried in the second u32 decomposition of its own ROM
//! residue is rejected, and rejected *by* the low-limb pin rather than
//! incidentally.
//!
//! The identity. `2^32 = 2p + 2` for `p = 2^31 - 1`, so the u32 window holds two
//! preimages of every M31 residue: `w` and `w + (p + 2) = w + 0x80000001`. The
//! immediate is bound by `composeU32(imm_limbs) - imm_felt - imm_sign * 2 = 0`,
//! and `imm_sign` is tied only to bit 31 of `imm_limbs[3]` — a bit the prover
//! also chooses. The second preimage raises the residue by exactly
//! `p + 2 == 2 (mod p)`, which is exactly what flipping `imm_sign` to one
//! subtracts, so the binding closes on both preimages: it is circular. `AUIPC
//! x10, 0x2` at pc `0x1000c` therefore admits `imm_limbs = [0x01, 0x20, 0, 0x80]`
//! beside the honest `[0, 0x20, 0, 0]` for the same ROM word `imm_felt = 0x2000`,
//! and `rd` receives `0x8001200d` instead of `0x1200c`.
//!
//! Why the ROM lookup cannot catch it. `programLookup` offers
//! `(pc, opcode_id, rd_addr, imm_felt, 0)`. The alias moves none of those five:
//! it changes how the row *decomposes* a ROM word it still names honestly. The
//! third test below confirms the `program_access` fingerprint is byte-identical,
//! which is the whole reason a decoded-program lookup is no defence here.
//!
//! Why the sibling range checks cannot catch it either. `imm_limbs[3]` stays a
//! byte and the `range_check_m31` residual `imm_limbs[3] - 128 * imm_sign` is
//! `0x80 - 0x80 = 0`, so the pair the immediate offers that table is `(1, 0)` —
//! a legal row. The second test asserts that against the table's own index
//! function, so "only the pin rejects this" is executable rather than prose.
//!
//! What the forgery must move, and why none of it is extra freedom. Beyond
//! `imm_limbs` and `imm_sign` the row commits `result` and `rd_next`. Both are
//! *determined* by the aliased immediate: the four carry constraints pin
//! `result` to the bytewise sum `pc + imm`, and `destinationResultConstraints`
//! pins `rd_next` to `result` for a nonzero `rd`. Leaving either honest would
//! break the adder or the destination write, and the row would be refused with
//! the pin deleted — coverage-shaped, not coverage. `pc`, `pc_limbs`,
//! `imm_felt`, `rd_addr`, `rd_prev`, `rd_clock_prev`, `clock`, `enabler` and the
//! destination inverse are all untouched.
//!
//! Attribution is row-local, and only row-local. The fix is a direct constraint,
//! so the second test below pins the forged row's failure to that one constraint
//! index and to no other: delete the pin and the row becomes admissible, which is
//! what makes that test a guard.
//!
//! What the end-to-end test does and does not show. It shows that an honest
//! `auipc` row can be committed, proven and verified — coverage nothing in the
//! repository had — and that the forged row never yields a proof. It cannot
//! attribute that refusal to the pin: the aliased value *is* an element of `rd`'s
//! access tuple, which the third test measures, so the global memory argument
//! would refuse the row whatever the direct constraints say. What the stage does
//! say is that the low-limb pin is a *direct constraint* and not a lookup: the
//! forged row never becomes a proof, where a forgery caught only by a
//! preprocessed table proves and loses at verification instead. Deleting the pin
//! would move this test's stage, not just its verdict.
//!
//! Runtime: three row-local tests in milliseconds; one end-to-end test costing
//! about seventy-five seconds of CPU — an honest proof plus verification, then
//! one aborted proof of the same nine-instruction guest. Bounded by
//! construction: one committed `auipc` row.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;

const harness = @import("committed_forgery_harness.zig");
const guest_elf = @import("guest_elf_fixture.zig");
const layout = @import("committed_row_layout.zig");
const schema = @import("../../frontends/riscv/air/lookups/tables/schema.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");

/// `AUIPC x10, 0x2`: `rd = pc + (0x2 << 12)`. U-type immediates are 4096-aligned,
/// so `imm_felt = 0x2000` and the honest low limb is zero — the property the pin
/// asserts. `x10` is the register the fixture epilogue publishes and is outside
/// the prologue's `x1`, `x2`, `x4`, `x5`.
const AUIPC_X10_0x2000: u32 = (0x2 << 12) | (10 << 7) | 0x17;

const SPEC = harness.Spec{ .body = &.{AUIPC_X10_0x2000}, .publish = 10 };

/// `p + 2 = 2^31 + 1`. The additive distance between the two u32 preimages of
/// one M31 residue, and therefore the entire forgery.
const ALIAS: u32 = 0x8000_0001;

/// Every column the forgery touches, named through the committed layout so a
/// reordered or renamed `auipc` column is a compile error rather than a probe
/// that silently lands on its neighbour.
const IMM_LIMBS = limbColumns("imm_limb_");
const RESULT = limbColumns("result_");
const RD_NEXT = limbColumns("rd_next_");
const IMM_SIGN = columnOf("imm_sign");
const IMM_FELT = columnOf("imm_felt");
const PC_LIMBS = limbColumns("pc_limb_");

/// Index of `imm_limbs[0] == 0` in `semantics/auipc.zig`'s constraint order:
/// enabler bit, pc composition, immediate composition, `imm_sign` bit, **the
/// low-limb pin**, four adder carries, three destination constraints, four
/// destination-write constraints, and the placement equality `semantic_eval`
/// appends. The count assertion below turns any change to that order into a
/// failure here rather than a probe silently naming a different obligation.
const LOW_LIMB_PIN: usize = 4;
const N_AUIPC_CONSTRAINTS: usize = 17;

fn columnOf(comptime name: []const u8) u32 {
    return @intCast(layout.columnOf(.auipc, name));
}

fn limbColumns(comptime prefix: []const u8) [4]u32 {
    return .{
        columnOf(prefix ++ "0"),
        columnOf(prefix ++ "1"),
        columnOf(prefix ++ "2"),
        columnOf(prefix ++ "3"),
    };
}

/// The u32 word four committed byte limbs decompose. Asserts each limb really is
/// a byte, which is a property of the row being read, not of the forgery: an
/// honest row is byte-decomposed and the range-check siblings say so.
fn wordOf(row: *const harness.Row, columns: [4]u32) u32 {
    var word: u32 = 0;
    for (columns, 0..) |column, index| {
        const limb = row.m31At(column).toU32();
        std.debug.assert(limb < 256);
        word |= limb << @as(u5, @intCast(index * 8));
    }
    return word;
}

fn byteLimbs(word: u32) [4]u32 {
    var limbs: [4]u32 = undefined;
    for (&limbs, 0..) |*limb, index| {
        limb.* = (word >> @as(u5, @intCast(index * 8))) & 0xff;
    }
    return limbs;
}

/// Four immediate limbs, the sign bit, four result limbs, four written limbs.
const N_FORGED_COLUMNS: usize = 13;

/// The aliased decomposition of whatever immediate the honest row carries, with
/// the adder output and the destination write it forces.
///
/// Both words wrap: `+% ALIAS` is the u32 window's second preimage, and the
/// forgery is only interesting because that wrap is invisible in M31.
fn aliasForgery(honest: *const harness.Row) [N_FORGED_COLUMNS]harness.ColumnValue {
    const immediate = byteLimbs(wordOf(honest, IMM_LIMBS) +% ALIAS);
    const result = byteLimbs(wordOf(honest, RESULT) +% ALIAS);

    var values: [N_FORGED_COLUMNS]harness.ColumnValue = undefined;
    var n: usize = 0;
    for (IMM_LIMBS, immediate) |column, value| {
        values[n] = .{ .column = column, .value = value };
        n += 1;
    }
    // Bit 31 of the aliased word is set, so the sign the range check reads back
    // out of `imm_limbs[3]` is one — and its `* 2` term is what absorbs `p + 2`.
    values[n] = .{ .column = IMM_SIGN, .value = 1 };
    n += 1;
    for (RESULT, result) |column, value| {
        values[n] = .{ .column = column, .value = value };
        n += 1;
    }
    for (RD_NEXT, result) |column, value| {
        values[n] = .{ .column = column, .value = value };
        n += 1;
    }
    std.debug.assert(n == values.len);
    return values;
}

/// The honest committed `auipc` row of the fixture guest, read out of the
/// witness generator rather than transcribed, so a witness-generation change
/// moves the baseline instead of desynchronising it from this test.
fn honestAuipcRow(guest: *const harness.Guest) !harness.Row {
    try std.testing.expectEqual(@as(usize, 1), try guest.familyRowCount(.auipc));
    return guest.honestRow(.auipc, 0);
}

// Runtime: milliseconds. One nine-instruction run and one 29-column row.
test "auipc alias: the honest row pins its immediate's low limb to zero" {
    try std.testing.expectEqual(
        N_AUIPC_CONSTRAINTS,
        semantic_eval.constraintCount(.auipc),
    );

    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestAuipcRow(&guest);
    try harness.expectAccepted(.auipc, honest.slice());

    // The honest witness is the one the pin describes: a 4096-aligned immediate
    // whose low byte is zero, carried with `imm_sign` clear.
    try std.testing.expectEqual(@as(u32, 0x2000), wordOf(&honest, IMM_LIMBS));
    try std.testing.expectEqual(M31.zero(), honest.m31At(IMM_LIMBS[0]));
    try std.testing.expectEqual(M31.zero(), honest.m31At(IMM_SIGN));
    try std.testing.expectEqual(M31.fromCanonical(0x2000), honest.m31At(IMM_FELT));

    // `rd` receives `pc + imm`, and the row sits where the fixture says.
    try std.testing.expectEqual(guest_elf.bodyPc(0), wordOf(&honest, PC_LIMBS));
    try std.testing.expectEqual(guest_elf.bodyPc(0) + 0x2000, wordOf(&honest, RESULT));
    try std.testing.expectEqual(wordOf(&honest, RESULT), wordOf(&honest, RD_NEXT));
    try std.testing.expectEqual(
        M31.fromCanonical(guest_elf.bodyClock(0)),
        honest.m31At(semantic_eval.clockColumn(.auipc)),
    );
}

// Runtime: milliseconds. Same shape as the test above.
test "auipc alias: the p + 2 decomposition fails only the low-limb pin" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestAuipcRow(&guest);

    var forged = honest;
    forged.apply(&aliasForgery(&honest));

    // The identity the forgery rests on: the second preimage raises the M31
    // residue by exactly two, which is what `imm_sign * 2` subtracts, so the
    // composition binding closes on a decomposition it was meant to exclude.
    try std.testing.expectEqual(
        M31.fromU64(wordOf(&honest, IMM_LIMBS)).add(M31.fromCanonical(2)),
        M31.fromU64(wordOf(&forged, IMM_LIMBS)),
    );
    try std.testing.expectEqual(@as(u32, 0x8000_2001), wordOf(&forged, IMM_LIMBS));
    // `rd` is handed a value 0x80000001 above the architectural one while the
    // ROM word it claims to have decoded is untouched.
    try std.testing.expectEqual(@as(u32, 0x8001_200d), wordOf(&forged, RD_NEXT));
    try std.testing.expectEqual(honest.m31At(IMM_FELT), forged.m31At(IMM_FELT));

    // Attribution. Exactly one direct constraint fails and it is the pin, so the
    // adder chain, the sign bit, both compositions and the destination write all
    // vanish on the forged row: delete the pin and the row is admissible.
    try harness.expectOnlyConstraint(.auipc, forged.slice(), LOW_LIMB_PIN);

    // The sibling that binds `imm_sign` accepts the alias. `imm_limbs[3]` is
    // still a byte and its residual is `0x80 - 128 * 1 = 0`, so the pair
    // `range_check_m31` is offered is a legal table row — asserted against the
    // table's own index function rather than asserted in a comment.
    _ = try schema.indexBase(.range_check_m31, &.{
        forged.m31At(IMM_LIMBS[0]),
        forged.m31At(IMM_LIMBS[3]).sub(M31.fromCanonical(128)),
    });
}

// Runtime: milliseconds.
test "auipc alias: the forged row asks the program bus for the honest tuple" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestAuipcRow(&guest);
    var forged = honest;
    forged.apply(&aliasForgery(&honest));

    // Why the decoded-program lookup was no defence: the alias changes the
    // row's *decomposition* of a ROM word whose five-element program tuple —
    // pc, opcode id, rd address, `imm_felt`, zero — it still offers unchanged.
    try std.testing.expectEqual(
        try harness.busFingerprint(.auipc, honest.slice(), .program_access),
        try harness.busFingerprint(.auipc, forged.slice(), .program_access),
    );
    // pc and clock are untouched, so the state chain sees the honest step too.
    try std.testing.expectEqual(
        try harness.busFingerprint(.auipc, honest.slice(), .registers_state),
        try harness.busFingerprint(.auipc, forged.slice(), .registers_state),
    );

    // The one bus the forgery does move is the register write, because the
    // aliased value *is* an element of `rd`'s access tuple. So the global memory
    // argument would refuse this row as well, whatever the pin does — which is
    // why attribution lives in the row-local test above and cannot live in the
    // end-to-end test below.
    try std.testing.expect(
        try harness.busFingerprint(.auipc, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.auipc, forged.slice(), .memory_access),
    );
}

// Runtime: about seventy-five seconds of CPU — one honest proof and
// verification plus one aborted proof of a nine-instruction guest, dominated by
// the fixed-size preprocessed lookup tables rather than by the guest.
test "auipc alias: the honest AUIPC proof verifies and the aliased row cannot be proven" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    // The honest half is the new coverage: `proof_admission_test.zig` promises
    // every RV32IM family reaches the backend and proves only MULH, so until
    // this line nothing proved an `auipc` row end to end. Without it, the
    // rejection below would also be satisfied by a guest that cannot be proven.
    try guest.proveAndVerify();

    const honest = try honestAuipcRow(&guest);
    const forgery = aliasForgery(&honest);
    // `.prover_constraints` is where the pin lives, so it is the stage to name —
    // but it is reached by this forgery whether or not the pin exists, because
    // the harness generates the interaction trace from the unmutated witness.
    // See the header: this half is reachability, not attribution.
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = .auipc } },
        .logical_row = 0,
        .values = &forgery,
    } }, .prover_constraints);
}
