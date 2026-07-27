//! A signed load whose committed sign witness is cleared is rejected, and
//! rejected *by* the sign residual range check rather than by any constraint.
//!
//! The forgery. The guest stores the byte `0x80` and loads it back with `LB`,
//! so the honest row commits `src_msb = 1` and
//! `result = [0x80, 0xff, 0xff, 0xff]` — the register receives `0xffffff80`. A
//! prover instead claims `src_msb = 0`. That zeroes
//! `signed_mask = is_signed * src_msb * 255`, which is the only value the three
//! sign-extension limbs are equated to, so the row may carry
//! `result = [0x80, 0, 0, 0]`: the register receives `0x80`, which is what
//! `LBU` computes. The `LH` case is the same forgery one limb up — the honest
//! halfword `0x8000` loads as `[0x00, 0x80, 0xff, 0xff]` and the forged row
//! claims `[0x00, 0x80, 0, 0]`, turning `LH` into `LHU`.
//!
//! Why attribution is the whole point. Every direct constraint still vanishes.
//! `src_msb = 0` is a bit, so `bit(src_msb)` holds. `(1 - is_signed) * src_msb`
//! holds because `is_signed` is one for `LB` and `LH`. The sign-extension
//! equalities hold because both of their sides moved together, the selected
//! byte is untouched, and every forged limb is still a byte, so no downstream
//! byte range sees anything unusual. That is why an early constraints-only
//! probe reported this hole as still open after it had been closed. The check
//! that refuses the row is the seven-bit residual `result[0] - src_msb * 128`
//! (`result[1]` for `LH`) requested into `range_check_m31`: with `src_msb = 0`
//! the residual is the whole sign byte, `128`, and `range_check_m31` admits a
//! second tuple element only below `128`. So the row-local tests assert both
//! halves — `evaluate` returns all zero, and the *only* failing obligation is
//! that request. Delete the two `entry.rangeM31` requests
//! `opcode_entries.loadStore` emits and those assertions fail, because the
//! forged row becomes admissible.
//!
//! Columns the forgery moves that the bug description does not name.
//! `dst.next` is pinned to `result` by `destinationResultConstraints` for every
//! load that writes a register, so the written register's sign-extension limbs
//! move with the result limbs. This is forced, not chosen: a row whose
//! `result` and `dst.next` disagree fails that direct constraint and would be
//! refused whatever the range check does — which is exactly the coverage-shaped
//! outcome a single-cell mutation produces here.
//!
//! What the end-to-end tests do and do not show. A row-local verdict does not
//! say a signed-load row can be committed and proven at all; the honest proof
//! below is that half, and it is the reason the two rejection tests are not
//! vacuous. The rejections themselves are reachability evidence, not
//! attribution, for two independent reasons.
//!
//!  - `dst.next` limbs are elements of the register access tuples this row
//!    offers to `memory_access`, so the forgery moves that bus and the global
//!    memory argument refuses the row whatever the sign residual does. No
//!    end-to-end forgery of this fix can avoid that: the sign-extension limbs
//!    are the register write. Deleting both `signRangeLookups` requests leaves
//!    the two end-to-end tests passing and fails only the row-local ones, which
//!    is the measured statement of where the guard lives.
//!  - The stage is now the one the fix belongs at, which is a weaker statement
//!    than it sounds. Both forgeries leave every direct constraint vanishing, so
//!    they reach a real proof and lose the global LogUp closure:
//!    `.verification`. That separates a lookup fix from a constraint fix, but it
//!    cannot separate *this* lookup from the register bus the same override
//!    moves. Pinning it rather than `.any` still keeps the tests honest about
//!    which half of the pipeline rejects.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");
const opcode_entries = @import("../../frontends/riscv/air/lookups/opcode_entries.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");

// ---------------------------------------------------------------------------
// The guest
// ---------------------------------------------------------------------------

/// A word-aligned scratch word inside the fixture's RW region, far from the
/// public output words the epilogue writes.
const SCRATCH_BASE: u32 = 0x001F_F000;

/// `LUI x6, 0x001ff`, `ADDI x7, x0, -128`, `SB x7, 0(x6)`, `LB x10, 0(x6)`,
/// `LUI x8, 0x8`, `SH x8, 4(x6)`, `LH x11, 4(x6)`.
///
/// The two signed loads read back bytes the guest itself stored, because the
/// fixture's one public input word is `{1, 2, 3, 4}` and no byte of it has its
/// high bit set. `x6`, `x7`, `x8`, `x10` and `x11` avoid the prologue's and
/// epilogue's `x1`, `x2`, `x4` and `x5`.
const BODY = [_]u32{
    0x001F_F337,
    0xF800_0393,
    0x0073_0023,
    0x0003_0503,
    0x0000_8437,
    0x0083_1223,
    0x0043_1583,
};

const LB_BODY_INDEX: usize = 3;
const LH_BODY_INDEX: usize = 6;

/// `LB`'s destination is published as output word 0; `LH`'s destination is
/// bound through the final-register block `public_logup` emits for all 32
/// registers.
const LB_RD: u5 = 10;
const LH_RD: u5 = 11;

const LB_RESULT: u32 = 0xFFFF_FF80;
const LH_RESULT: u32 = 0xFFFF_8000;

const SPEC = guest_elf.Spec{ .body = &BODY, .publish = LB_RD };

// ---------------------------------------------------------------------------
// The forgeries
// ---------------------------------------------------------------------------

/// Every column the forgeries touch, named through the committed layout so a
/// reordered or renamed `load_store` column is a compile error rather than a
/// probe that silently lands on its neighbour.
const SRC_MSB = layout.columnOf(.load_store, "src_msb");
const RESULT = limbColumns("result");
const DST_NEXT = limbColumns("dst_next");

/// The sign byte of a byte load is `result[0]`; of a halfword load,
/// `result[1]`. Everything above it is the sign extension the forgery zeroes.
const LB_SIGN_LIMB: usize = 0;
const LH_SIGN_LIMB: usize = 1;

/// Position of each sign residual in the row's emitted entry list. `load_store`
/// emits, in order: the program tuple, two state-chain tuples, the `rs1`,
/// `src` and `dst` access chains with their clock gaps, the aligned-address
/// range, the base-address `range_check_m31` pair, and finally the `LB` and
/// `LH` sign residuals. Pinning the position names *which* of the row's three
/// `range_check_m31` requests failed; the domain alone does not.
///
/// The two sign residuals are the last entries the family emits, so pinning the
/// entry count is what turns a reordered or extended emission list into a
/// failure here instead of a probe silently naming a neighbouring request.
const LB_SIGN_REQUEST: usize = 14;
const LH_SIGN_REQUEST: usize = 15;
const N_LOAD_STORE_ENTRIES: usize = 16;

fn limbColumns(comptime prefix: []const u8) [4]usize {
    return .{
        layout.columnOf(.load_store, prefix ++ "_0"),
        layout.columnOf(.load_store, prefix ++ "_1"),
        layout.columnOf(.load_store, prefix ++ "_2"),
        layout.columnOf(.load_store, prefix ++ "_3"),
    };
}

fn cell(comptime column: usize, comptime value: u32) harness.ColumnValue {
    return .{ .column = @intCast(column), .value = value };
}

/// `LB` claiming the `LBU` result: the sign witness and every limb above the
/// selected byte go to zero, in `result` and in the register write that mirrors
/// it.
const LB_FORGERY = [_]harness.ColumnValue{
    cell(SRC_MSB, 0),
    cell(RESULT[1], 0),
    cell(RESULT[2], 0),
    cell(RESULT[3], 0),
    cell(DST_NEXT[1], 0),
    cell(DST_NEXT[2], 0),
    cell(DST_NEXT[3], 0),
};

/// `LH` claiming the `LHU` result. Two limbs sit above a halfword, so this
/// forgery is two columns narrower than the byte one.
const LH_FORGERY = [_]harness.ColumnValue{
    cell(SRC_MSB, 0),
    cell(RESULT[2], 0),
    cell(RESULT[3], 0),
    cell(DST_NEXT[2], 0),
    cell(DST_NEXT[3], 0),
};

// ---------------------------------------------------------------------------
// Locating the committed row
// ---------------------------------------------------------------------------

/// Family-relative index of the committed row body instruction `body_index`
/// retired, counted out of the run rather than transcribed, so an added load or
/// store anywhere in the fixture moves the index instead of silently pointing
/// the forgery at another row.
fn bodyLogicalRow(guest: *const harness.Guest, body_index: usize) !usize {
    const target = guest_elf.bodyRow(body_index);
    var logical: usize = 0;
    for (guest.run.execution_trace.rows.items, 0..) |row, index| {
        if (index == target) return logical;
        if (try trace_mod.proofOpcodeFamily(row.opcode) == .load_store) logical += 1;
    }
    return error.NoSuchBodyRow;
}

/// The honest committed row of body instruction `body_index`, read out of the
/// witness generator rather than transcribed, and checked to be the
/// instruction under test rather than a neighbouring memory operation.
fn honestLoadRow(guest: *const harness.Guest, body_index: usize) !harness.Row {
    const row = try guest.honestRow(.load_store, try bodyLogicalRow(guest, body_index));
    try std.testing.expectEqual(
        M31.fromCanonical(guest_elf.bodyPc(body_index)),
        row.m31At(semantic_eval.pcColumn(.load_store)),
    );
    return row;
}

/// Assert the honest row is the sign-extended load: the sign byte, then `0xff`
/// in every limb above it, and a set sign witness.
fn expectSignExtended(row: *const harness.Row, sign_limb: usize, sign_byte: u32) !void {
    try std.testing.expectEqual(M31.one(), row.m31At(SRC_MSB));
    try std.testing.expectEqual(M31.fromCanonical(sign_byte), row.m31At(RESULT[sign_limb]));
    for (RESULT[sign_limb + 1 ..]) |column| {
        try std.testing.expectEqual(M31.fromCanonical(0xff), row.m31At(column));
    }
}

/// Assert the forged row is coherent and refused only by the sign residual of
/// `request`, whose out-of-range element is the unmasked sign byte itself.
fn expectOnlySignRange(
    row: *const harness.Row,
    sign_limb: usize,
    request: usize,
) !void {
    // The load-bearing half of the attribution: the coordinated forgery
    // satisfies the AIR's direct constraints, so the rejection below is not a
    // sign-extension equality, a byte range or the register write in disguise.
    const evaluation = try semantic_eval.evaluate(.load_store, row.slice(), QM31.one());
    try std.testing.expect(evaluation.allZero());

    try std.testing.expectEqual(
        N_LOAD_STORE_ENTRIES,
        opcode_entries.entryCount(.load_store),
    );
    const rejection = try harness.expectOnlyLookup(
        .load_store,
        row.slice(),
        .range_check_m31,
    );
    try std.testing.expectEqual(request, rejection.index);
    try std.testing.expectEqual(@as(usize, 2), rejection.tuple().len);
    try std.testing.expectEqual(M31.zero(), try rejection.tuple()[0].tryIntoM31());
    // With the sign witness cleared the residual is the whole sign byte, so the
    // failing element is the forged result limb — which is what names this
    // request as the sign residual rather than the base-address pair.
    try std.testing.expectEqual(
        row.m31At(RESULT[sign_limb]),
        try rejection.tuple()[1].tryIntoM31(),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(128),
        try rejection.tuple()[1].tryIntoM31(),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Runtime: milliseconds. One fifteen-instruction run, no proof.
test "load sign: the guest sign-extends both signed loads" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    try std.testing.expectEqual(guest_elf.instructionCount(SPEC), guest.run.step_count);
    try std.testing.expectEqual(LB_RESULT, guest.run.final_regs[LB_RD]);
    try std.testing.expectEqual(LH_RESULT, guest.run.final_regs[LH_RD]);

    // Eight committed `load_store` rows: the prologue's `LW`, the body's two
    // stores and two loads, and the epilogue's three stores. Both signed loads
    // are therefore addressed by a family-relative index, not by row 0.
    try std.testing.expectEqual(@as(usize, 8), try guest.familyRowCount(.load_store));
    try std.testing.expectEqual(@as(usize, 2), try bodyLogicalRow(&guest, LB_BODY_INDEX));
    try std.testing.expectEqual(@as(usize, 4), try bodyLogicalRow(&guest, LH_BODY_INDEX));

    // The sign-extended byte load reaches public output, so a reader of the
    // statement can see the value the forgeries contradict.
    try std.testing.expectEqual(@as(u32, 4), guest.run.output_len);
    try std.testing.expect(guest.run.output != null);
    try std.testing.expectEqual(
        LB_RESULT,
        std.mem.readInt(u32, guest.run.output.?[0..4], .little),
    );
    try std.testing.expectEqual(SCRATCH_BASE, guest.run.execution_trace
        .rows.items[guest_elf.bodyRow(LB_BODY_INDEX)].mem_addr);
}

// Runtime: milliseconds. One fifteen-instruction run and one 56-column row.
test "load sign: the LBU-shaped LB row satisfies every constraint and fails only its sign range" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestLoadRow(&guest, LB_BODY_INDEX);
    try harness.expectAccepted(.load_store, honest.slice());
    try expectSignExtended(&honest, LB_SIGN_LIMB, 0x80);

    var forged = honest;
    forged.apply(&LB_FORGERY);
    // The forged row is exactly the `LBU` witness for the same memory word.
    try std.testing.expectEqual(M31.fromCanonical(0x80), forged.m31At(RESULT[0]));
    for (RESULT[1..]) |column| {
        try std.testing.expectEqual(M31.zero(), forged.m31At(column));
    }

    try expectOnlySignRange(&forged, LB_SIGN_LIMB, LB_SIGN_REQUEST);
}

// Runtime: milliseconds. Same shape as the test above.
test "load sign: the LHU-shaped LH row satisfies every constraint and fails only its sign range" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestLoadRow(&guest, LH_BODY_INDEX);
    try harness.expectAccepted(.load_store, honest.slice());
    try expectSignExtended(&honest, LH_SIGN_LIMB, 0x80);
    // The low limb of a halfword load carries no sign information, so the
    // forgery must leave it alone; only the extension above it moves.
    try std.testing.expectEqual(M31.zero(), honest.m31At(RESULT[0]));

    var forged = honest;
    forged.apply(&LH_FORGERY);
    try std.testing.expectEqual(honest.m31At(RESULT[0]), forged.m31At(RESULT[0]));
    try std.testing.expectEqual(honest.m31At(RESULT[1]), forged.m31At(RESULT[1]));

    try expectOnlySignRange(&forged, LH_SIGN_LIMB, LH_SIGN_REQUEST);
}

// Runtime: milliseconds.
test "load sign: clearing the sign witness also moves the register write bus" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestLoadRow(&guest, LB_BODY_INDEX);
    var forged = honest;
    forged.apply(&LB_FORGERY);

    // The sign-extension limbs of `result` are the register write, so they are
    // also elements of the access tuples this row offers to `memory_access`.
    // The global memory argument therefore refuses this forgery on its own,
    // whatever the sign residual does — which is why the end-to-end tests below
    // are evidence that the forged row is refused in production, not evidence
    // about which check refuses it. Attribution to the two `signRangeLookups`
    // requests lives in the row-local tests above, and no end-to-end forgery
    // can supply it.
    try std.testing.expect(
        try harness.busFingerprint(.load_store, honest.slice(), .memory_access) !=
            try harness.busFingerprint(.load_store, forged.slice(), .memory_access),
    );
    // The claim is specific to that bus: the row's state-chain and program
    // tuples are untouched, so the difference above is the register write.
    try std.testing.expectEqual(
        try harness.busFingerprint(.load_store, honest.slice(), .registers_state),
        try harness.busFingerprint(.load_store, forged.slice(), .registers_state),
    );
    try std.testing.expectEqual(
        try harness.busFingerprint(.load_store, honest.slice(), .program_access),
        try harness.busFingerprint(.load_store, forged.slice(), .program_access),
    );
}

// Runtime: about thirty seconds — one proof of a fifteen-instruction guest,
// dominated by the fixed-size preprocessed lookup tables rather than by the
// guest. Bounded by construction: eight committed `load_store` rows.
test "load sign: the honest signed-load proof verifies" {
    // Without this half the two rejection tests below are also satisfied by a
    // guest that cannot be proven at all. Before this file nothing in the
    // repository proved a signed `load_store` row end to end.
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try guest.proveAndVerify();
}

// Runtime: about thirty seconds — one proof of the same guest.
test "load sign: the committed LB sign forgery is refused in production" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = .load_store } },
        .logical_row = @intCast(try bodyLogicalRow(&guest, LB_BODY_INDEX)),
        .values = &LB_FORGERY,
    } }, .verification);
}

// Runtime: about thirty seconds — one proof of the same guest.
test "load sign: the committed LH sign forgery is refused in production" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try guest.expectRejectedAt(.{ .main_row = .{
        .target = .{ .opcode = .{ .family = .load_store } },
        .logical_row = @intCast(try bodyLogicalRow(&guest, LH_BODY_INDEX)),
        .values = &LH_FORGERY,
    } }, .verification);
}
