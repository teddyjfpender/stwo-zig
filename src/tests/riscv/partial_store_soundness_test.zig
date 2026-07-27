//! A byte store may rewrite the byte it marked and nothing else, and the bytes
//! it leaves alone are rejected *by* the unmarked-byte preservation constraints.
//!
//! The bug. `SB`/`SH` commit the whole destination memory word as `dst.previous`
//! and `dst.next`, but the pinned Stark-V layout tied only the *marked* limbs of
//! `dst.next` to the stored data. The other three limbs of a byte store's target
//! word were therefore free prover choices that the memory access chain wrote
//! back, so `SB` doubled as an arbitrary three-byte write. The fix binds every
//! unmarked limb to `dst.previous`, gated on `is_sb + is_sh` so a full-word `SW`
//! keeps overwriting all four bytes.
//!
//! The guest. `SW` a known word to a data address, `SB` one byte into it, then
//! `LW` it back, so the byte store's effect on the *whole* word reaches public
//! output: the guest publishes `0x04035501`, which is the input word
//! `0x04030201` with byte 1 replaced. A row-local test alone cannot say the
//! forged row is reachable, so the last test proves the honest guest end to end
//! before forging it.
//!
//! The forgery. The `SB` row's committed `dst.next` limbs are replaced with
//! `0xCCBB55AA`: the marked limb keeps the honestly stored `0x55`, so the store
//! itself is still exactly what the program asked for, and the three unmarked
//! limbs carry the attacker's bytes. Nothing else moves — `dst_next_*` is the
//! only column block the forgery touches. That is deliberate and is what makes
//! the row-local rejection attributable: the marked-byte constraint, the
//! read-only bindings on `rs1` and `src`, the marker/shift witnesses, the
//! destination write-enable and the store's zero result witness are all
//! untouched and all still vanish, so the only obligations left to reject the
//! row are the four preservation constraints the fix added.
//!
//! Why attribution is row-local, and why the end-to-end half cannot supply it.
//! `dst.next` is not only witness: its limbs are elements of the `memory_access`
//! tuple the row offers the bus. So the forged row moves that bus as well as
//! breaking the four preservation constraints, and the global memory argument
//! would refuse it even with the fix deleted. Deleting the fix and rerunning
//! confirms it: the row-local tests below fail and this one still passes.
//! What the end-to-end stage does say is that the fix is a *direct constraint*:
//! the forged row never becomes a proof, where a forgery caught only by a
//! preprocessed table proves and loses at verification. Attribution to the
//! specific constraint lives entirely in the row-local tests, which name one
//! index per forged limb.
//!
//! Completeness. The same guest's `SW` row overwrites all four bytes of a word
//! that was previously zero. It is admissible, which is the evidence that the
//! `is_sb + is_sh` gate does not over-constrain a full-word store — every limb
//! of that row is unmarked, so an ungated preservation constraint would reject
//! it. The other half of that test forges the `SW` row to leave one byte at its
//! previous value and shows the *word* constraint still rejects it, so nothing
//! about `SW` was weakened either.
//!
//! Coverage this file does not claim. The gate is `is_sb + is_sh`; only the
//! `is_sb` half is exercised here, because the guest is deliberately the three
//! memory operations the bug needs and nothing more. `SH`'s two-limb marker set
//! relies on the same four constraints and on `semantics/load_store.zig`'s own
//! row-level test.
//!
//! Runtime: four tests in milliseconds, plus about a minute for the end-to-end
//! case, which proves a thirteen-instruction guest twice.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("committed_forgery_harness.zig");
const layout = @import("committed_row_layout.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");

// ---------------------------------------------------------------------------
// The guest
// ---------------------------------------------------------------------------

/// `LUI x3, 0x200`, `SW x5, -1024(x3)`, `ADDI x7, x0, 0x55`,
/// `SB x7, -1023(x3)`, `LW x10, -1024(x3)`.
///
/// `x5` already holds the public input word after the fixture prologue, so the
/// stored word costs no instruction. `x3` addresses the data word from above
/// because `0x001FFC00` is not reachable as a `LUI` immediate plus a signed
/// twelve-bit offset from below. `x10` is the fixture's default publish
/// register, so the reloaded word is the guest's public output.
const BODY = [_]u32{
    0x0020_01B7,
    0xC051_A023,
    0x0550_0393,
    0xC071_80A3,
    0xC001_A503,
};

const SPEC = guest_elf.Spec{ .body = &BODY };

/// Aligned data word the body stores to: the lowest word of the fixture's stack
/// region, which nothing else in the guest touches.
const DATA_ADDR: u32 = 0x001F_FC00;

/// The word the `SW` writes — the fixture's public input word, little-endian.
const STORED_WORD: u32 = 0x0403_0201;

/// The byte the `SB` writes and the limb it marks.
const STORED_BYTE: u32 = 0x55;
const MARKED_LIMB: usize = 1;
const UNMARKED_LIMBS = [_]usize{ 0, 2, 3 };

/// The architecturally correct word after the byte store, reloaded by the `LW`
/// and published as output word 0.
const PATCHED_WORD: u32 = 0x0403_5501;

/// What a forger would leave in memory instead: the marked limb keeps the
/// honestly stored byte, every unmarked limb is the attacker's choice.
const FORGED_WORD: u32 = 0xCCBB_55AA;

/// `load_store` rows in execution order: the prologue's input `LW`, the body's
/// `SW`, `SB` and `LW`, then the epilogue's three stores.
const SW_LOGICAL_ROW: usize = 1;
const SB_LOGICAL_ROW: usize = 2;
const LOAD_STORE_ROWS: usize = 7;

// ---------------------------------------------------------------------------
// The committed row and the constraints under test
// ---------------------------------------------------------------------------

/// `dst` is the written access of a `load_store` row, which is the memory word
/// for a store.
const DST_SLOT: usize = 0;
const DST_PREVIOUS = limbColumns("dst_prev");
const DST_NEXT = limbColumns("dst_next");
const MARKERS = limbColumns("marker");

fn limbColumns(comptime prefix: []const u8) [4]usize {
    return .{
        layout.columnOf(.load_store, prefix ++ "_0"),
        layout.columnOf(.load_store, prefix ++ "_1"),
        layout.columnOf(.load_store, prefix ++ "_2"),
        layout.columnOf(.load_store, prefix ++ "_3"),
    };
}

/// Direct constraints of `semantics/load_store.zig`, in the order `evaluate`
/// appends them and therefore the order `harness.attribute` reports. Counting
/// them out is the only map there is; `constraintCount` is asserted below so a
/// reordered or resized set fails loudly here instead of moving a probe onto a
/// neighbouring obligation.
///
///   0        `active` is a bit
///   1..8     each opcode flag is a bit
///   9, 10    `src_msb` is a bit and is zero outside signed loads
///   11..14   each marker is a bit
///   15..17   `shift_amount`, `src_addr_selector`, `dst_addr_selector`
///   18..20   marker sum and shift id per access width
///   21..23   sign fill of a byte load's high limbs
///   24..31   per limb: the byte load's selected byte, then `SB`'s stored byte
///   32..33   sign fill of a half load's high limbs
///   34..41   half-load halves, then `SH`'s halves
///   42..45   per limb: `LW` result and `SW` full-word overwrite
///   46..53   read-only `rs1`, then read-only `src`, per limb
///   54..57   per limb: `SB`/`SH` preserve every unmarked byte  <- the fix
///   58..60   destination write-enable witness
///   61..64   load result link
///   65..68   a store's unused result witness is zero
///   69       component placement, appended by `semantic_eval`
const WORD_STORE_BASE: usize = 42;
const PARTIAL_STORE_BASE: usize = 54;
const N_LOAD_STORE_CONSTRAINTS: usize = 70;

/// Within the per-limb pairs at 24..31, the second of each pair is `SB`'s
/// stored-byte constraint. It is the pinned Stark-V check that already bound the
/// marked limb, and naming it is how the negative control below shows the fix is
/// not what binds that limb.
const STORED_BYTE_BASE: usize = 25;
const STORED_BYTE_STRIDE: usize = 2;

// ---------------------------------------------------------------------------
// Forgeries
// ---------------------------------------------------------------------------

/// Absolute committed values for one forged row. Only `dst_next_*` moves, so
/// four entries is the whole budget.
const Forgery = struct {
    buffer: [4]harness.ColumnValue = undefined,
    len: usize = 0,

    fn setLimb(self: *Forgery, limb: usize, value: u32) void {
        self.buffer[self.len] = .{ .column = @intCast(DST_NEXT[limb]), .value = value };
        self.len += 1;
    }

    fn values(self: *const Forgery) []const harness.ColumnValue {
        return self.buffer[0..self.len];
    }
};

fn byteOf(word: u32, limb: usize) u32 {
    return (word >> @intCast(8 * limb)) & 0xff;
}

/// Replace one limb of the destination word with `value`.
fn singleByteForgery(limb: usize, value: u32) Forgery {
    var forgery = Forgery{};
    forgery.setLimb(limb, value);
    return forgery;
}

/// Replace every unmarked limb: the bug's full shape, a byte store that
/// rewrites the rest of the word. The marked limb is left honest, so the row
/// still claims exactly the byte the program stored.
fn wholeWordForgery() Forgery {
    var forgery = Forgery{};
    for (UNMARKED_LIMBS) |limb| forgery.setLimb(limb, byteOf(FORGED_WORD, limb));
    return forgery;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn limbsOf(row: *const harness.Row, columns: [4]usize) [4]M31 {
    var out: [4]M31 = undefined;
    for (&out, columns) |*value, column| value.* = row.m31At(column);
    return out;
}

fn wordLimbs(word: u32) [4]M31 {
    var out: [4]M31 = undefined;
    for (&out, 0..) |*value, limb| value.* = M31.fromCanonical(byteOf(word, limb));
    return out;
}

/// The honest committed `load_store` row `logical_row`, read out of the witness
/// generator rather than transcribed, so a witness-generation change moves the
/// baseline instead of desynchronising it from this test.
fn honestLoadStoreRow(guest: *const harness.Guest, logical_row: usize) !harness.Row {
    try std.testing.expectEqual(LOAD_STORE_ROWS, try guest.familyRowCount(.load_store));
    return guest.honestRow(.load_store, logical_row);
}

fn expectConstraintFailures(
    columns: []const QM31,
    first: usize,
    count: usize,
) !void {
    switch (try harness.attribute(.load_store, columns)) {
        .constraints => |failure| {
            try std.testing.expectEqual(first, failure.index);
            try std.testing.expectEqual(count, failure.count);
            try std.testing.expectEqual(N_LOAD_STORE_CONSTRAINTS, failure.total);
        },
        .accepted => {
            std.debug.print(
                "expected constraints {d}.. to fail; the row is admissible\n",
                .{first},
            );
            return error.TestUnexpectedResult;
        },
        .lookup => |rejection| {
            std.debug.print(
                "expected constraints {d}.. to fail; request {d} on {s} rejected instead\n",
                .{ first, rejection.index, @tagName(rejection.domain) },
            );
            return error.TestUnexpectedResult;
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Runtime: milliseconds. One thirteen-instruction run and no proof.
test "partial store: the honest SB row marks one byte and preserves the other three" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();

    // The whole index map above is only valid for this constraint count.
    try std.testing.expectEqual(
        N_LOAD_STORE_CONSTRAINTS,
        semantic_eval.constraintCount(.load_store),
    );
    // The named columns and the access-block arithmetic must land together, so
    // `dst_next_*` is the written access's `next` block and not a neighbour.
    inline for (0..4) |limb| {
        try std.testing.expectEqual(
            layout.nextLimbColumn(.load_store, DST_SLOT, limb),
            DST_NEXT[limb],
        );
        try std.testing.expectEqual(
            layout.previousLimbColumn(.load_store, DST_SLOT, limb),
            DST_PREVIOUS[limb],
        );
    }

    const honest = try honestLoadStoreRow(&guest, SB_LOGICAL_ROW);
    try harness.expectAccepted(.load_store, honest.slice());

    // The row is the byte store the body asked for: it consumes the word the
    // `SW` left and emits that word with exactly the marked byte replaced.
    try std.testing.expectEqual(
        M31.fromCanonical(DATA_ADDR),
        honest.m31At(layout.accessOffset(.load_store, DST_SLOT)),
    );
    try std.testing.expectEqualSlices(
        M31,
        &wordLimbs(STORED_WORD),
        &limbsOf(&honest, DST_PREVIOUS),
    );
    try std.testing.expectEqualSlices(
        M31,
        &wordLimbs(PATCHED_WORD),
        &limbsOf(&honest, DST_NEXT),
    );

    // The marker set is what the fix's gate consults, so the forgeries below
    // are only about unmarked limbs if the committed markers say so.
    try std.testing.expectEqual(M31.one(), honest.m31At(MARKERS[MARKED_LIMB]));
    try std.testing.expectEqual(
        M31.fromCanonical(STORED_BYTE),
        honest.m31At(DST_NEXT[MARKED_LIMB]),
    );
    for (UNMARKED_LIMBS) |limb| {
        try std.testing.expectEqual(M31.zero(), honest.m31At(MARKERS[limb]));
        try std.testing.expectEqual(
            honest.m31At(DST_PREVIOUS[limb]),
            honest.m31At(DST_NEXT[limb]),
        );
    }

    // The byte store's effect on the whole word is publicly observable: the
    // body reloads it and the epilogue publishes it, so a forged unmarked byte
    // contradicts the statement rather than an internal witness only.
    try std.testing.expectEqual(PATCHED_WORD, guest.run.final_regs[SPEC.publish]);
    try std.testing.expectEqual(@as(u32, 4), guest.run.output_len);
    try std.testing.expect(guest.run.output != null);
    try std.testing.expectEqual(
        PATCHED_WORD,
        std.mem.readInt(u32, guest.run.output.?[0..4], .little),
    );
}

// Runtime: milliseconds. Same run, three row-local evaluations.
test "partial store: each unmarked byte of dst.next fails only its own preservation constraint" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestLoadStoreRow(&guest, SB_LOGICAL_ROW);

    // One limb at a time, so the failing constraint is named rather than
    // counted: limb `k` must fail constraint `PARTIAL_STORE_BASE + k` and no
    // other. `expectOnlyConstraint` asserts the count is one, which is the
    // load-bearing half — a second failure would mean the forged row is
    // incoherent somewhere the bug description does not mention.
    for (UNMARKED_LIMBS) |limb| {
        var forged = honest;
        forged.apply(singleByteForgery(limb, byteOf(FORGED_WORD, limb)).values());
        try harness.expectOnlyConstraint(
            .load_store,
            forged.slice(),
            PARTIAL_STORE_BASE + limb,
        );
    }

    // Negative control. The marked limb is bound by the pinned stored-byte
    // constraint, not by the fix, so moving it must be attributed there. Without
    // this the three assertions above could be read as "the row rejects any
    // change to `dst.next`", which was already true of the marked limb and is
    // exactly what the bug left untrue of the other three.
    const UNRELATED_BYTE: u32 = 0x99;
    try std.testing.expect(UNRELATED_BYTE != STORED_BYTE);
    var marked = honest;
    marked.apply(singleByteForgery(MARKED_LIMB, UNRELATED_BYTE).values());
    try harness.expectOnlyConstraint(
        .load_store,
        marked.slice(),
        STORED_BYTE_BASE + STORED_BYTE_STRIDE * MARKED_LIMB,
    );
}

// Runtime: milliseconds. Same run, one row-local evaluation.
test "partial store: corrupting the rest of the word fails only the three unmarked constraints" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestLoadStoreRow(&guest, SB_LOGICAL_ROW);

    var forged = honest;
    forged.apply(wholeWordForgery().values());

    // The forged row claims a whole different memory word while still storing
    // exactly the byte the program stored, which is the bug: three of the four
    // committed limbs were free.
    try std.testing.expectEqualSlices(
        M31,
        &wordLimbs(FORGED_WORD),
        &limbsOf(&forged, DST_NEXT),
    );
    try std.testing.expectEqual(
        honest.m31At(DST_NEXT[MARKED_LIMB]),
        forged.m31At(DST_NEXT[MARKED_LIMB]),
    );

    // Exactly three direct constraints fail, the first being the preservation
    // constraint of the lowest unmarked limb. The test above named one index
    // per limb, so a first index of `PARTIAL_STORE_BASE` and a count of three
    // is the preservation block of limbs 0, 2 and 3 and nothing else: every
    // other obligation of the row still vanishes.
    try expectConstraintFailures(
        forged.slice(),
        PARTIAL_STORE_BASE + UNMARKED_LIMBS[0],
        UNMARKED_LIMBS.len,
    );
}

// Runtime: milliseconds. Same run, two row-local evaluations.
test "partial store completeness: SW still overwrites all four bytes of the word" {
    var guest = try harness.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    const honest = try honestLoadStoreRow(&guest, SW_LOGICAL_ROW);
    try harness.expectAccepted(.load_store, honest.slice());

    // The `SW` writes a word that was zero, so every limb of `dst.next`
    // differs from `dst.previous`, and `SW` marks none of them. An ungated
    // preservation constraint would therefore reject this row: its
    // admissibility is the evidence that `is_sb + is_sh` does not
    // over-constrain a full-word store.
    for (0..4) |limb| {
        try std.testing.expectEqual(M31.zero(), honest.m31At(MARKERS[limb]));
        try std.testing.expectEqual(M31.zero(), honest.m31At(DST_PREVIOUS[limb]));
        try std.testing.expect(!honest.m31At(DST_NEXT[limb]).eql(M31.zero()));
    }
    try std.testing.expectEqualSlices(
        M31,
        &wordLimbs(STORED_WORD),
        &limbsOf(&honest, DST_NEXT),
    );

    // Nothing about `SW` was weakened either: reverting limb 0 to the zero the
    // word already held is still rejected, by that limb's word constraint. `SW`
    // is a full-word overwrite before and after the fix.
    const PREVIOUS_BYTE: u32 = 0;
    var forged = honest;
    forged.apply(singleByteForgery(0, PREVIOUS_BYTE).values());
    try harness.expectOnlyConstraint(.load_store, forged.slice(), WORD_STORE_BASE + 0);
}

// Runtime: about a minute — two proofs of a thirteen-instruction guest,
// dominated by the fixed-size preprocessed lookup tables rather than by the
// guest. Bounded by construction: seven committed `load_store` rows.
test "partial store: the honest guest proves and verifies and the corrupted word row does not" {
    // The honest half is the coverage `proof_admission_test.zig` never had for
    // this family: before this test nothing in the repository proved a
    // `load_store` byte store end to end, and a rejection test without it would
    // also be satisfied by a guest that cannot be proven at all.
    //
    // The forged half is reachability, not attribution. The stage is
    // `prover_constraints` because that is where a direct-constraint fix lives —
    // an unsatisfied direct constraint stops the prover before a proof exists —
    // but in this pipeline the same stage is reached for a second, independent
    // reason: the override moves an active `memory_access` tuple while the LogUp
    // columns were generated from the un-mutated witness, so the composition
    // check refuses the trace even with the fix deleted. The bridge to
    // attribution is the shared recipe: `wholeWordForgery` is byte-for-byte the
    // row the test above proves is rejected only by constraints 54, 56 and 57.
    const forgery = wholeWordForgery();
    try harness.expectHonestProofAndForgedRejection(
        std.testing.allocator,
        "partial store guest (SW then SB then LW readback)",
        SPEC,
        .{
            .target = .{ .opcode = .{ .family = .load_store } },
            .logical_row = SB_LOGICAL_ROW,
            .values = forgery.values(),
        },
        .prover_constraints,
    );
}
