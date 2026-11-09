//! Malicious prover, stale register read: a locally perfect row that only
//! global memory closure can refuse.
//!
//! The attack. The shared fixture retires three `ADDI`s — `x3 := 7`,
//! `x3 := x3 + 1`, `x6 := x3 + 1` — so `x3` has two real historical versions
//! and the third instruction is the only consumer of the newer one. The
//! adversarial prover rewrites that third row to consume the *older* real
//! version: `rs1_prev = 7` at the access clock of the first write, re-emitted
//! unchanged as `rs1_next = 7`, with the destination coherently recomputed to
//! `x6 = 8`. Nothing in the row is inconsistent with itself. The addition is
//! right, the byte ranges hold, the read-only source binding holds
//! (`next == previous`), the clock gap is still positive and in range, and the
//! program and state tuples are untouched. `harness.staleRead` is exactly this
//! row, and every value it names is a value the run really produced.
//!
//! Why this is not a post-hoc mutation. The forgery is installed through the
//! production witness hook *before* lookup ingestion, so Tree 1, the lookup
//! multiplicities and Tree 2 are all generated from the forged witness, and the
//! Fiat-Shamir challenges are drawn over commitments to it. The prover here is
//! not editing a finished proof; it is choosing a different witness for the
//! same public statement and proving that.
//!
//! What the rejection means. The pinned stage is `.verification` with
//! `error.LogupSumNonZero`: the forged row survives every row-local check the
//! prover applies and does produce a complete proof, and the verifier's global
//! LogUp cancellation is what refuses it. That is the strongest form this
//! evidence can take. A rejection at `.prover_constraints` would have said some
//! direct constraint already covered the row, and a rejection at
//! `.precommit_ingestion` would have said the row was structurally malformed;
//! neither would show that the *global* memory argument is load-bearing.
//!
//! Attribution, in three widening steps, so "rejected" is never the whole
//! claim:
//!
//!  - row-locally the forgery is ADMISSIBLE (`committed.expectAccepted`), and
//!    only the `memory_access` bus fingerprint moves — the register-state and
//!    program buses are bit-identical, so no collateral disturbance can explain
//!    the rejection;
//!  - the moved tuple is named exactly: the forged row consumes the very tuple
//!    body row 1 already consumed, and orphans the tuple body row 1 emitted, so
//!    the access chain is double-spent at a named address and clock rather than
//!    merely different;
//!  - and the same forged transaction re-run in `.relation_diagnostic` mode
//!    shows `memory_access` is the ONLY one of the twelve relation domains
//!    whose committed sum fails to cancel against the public boundary. A test
//!    that only said "some LogUp sum was non-zero" would also pass if the
//!    forgery had broken the program bus instead.
//!
//! Runtime: about 40 s. One `.prove` run whose verification must fail, plus two
//! `.relation_diagnostic` runs, which stop before proof assembly. The row-local
//! tests are milliseconds. The honest proof-and-Sail leg is paid once for all
//! four attacks by `malicious_prover_harness.zig` and is deliberately not
//! repeated here.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const riscv_cpu = @import("stwo_riscv_cpu_integration");
const frontend = @import("stwo_riscv_frontend");
const access_clock = frontend.access_clock;
const entry_mod = frontend.air.lookups.entry;
const opcode_entries = frontend.air.lookups.opcode_entries;
const orchestration = frontend.testing.prover_orchestration;
const prover_mod = frontend.prover_mod;

const committed = @import("committed_forgery_harness.zig");
const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("malicious_prover_harness.zig");

/// The register the fixture writes twice and reads once.
const SOURCE_REG: u32 = 3;

/// Family-relative index of each body `ADDI`. The prologue retires no
/// `base_alu_imm` row, so the three body instructions are logical rows 0..2 and
/// the epilogue's two `ADDI`s follow them.
const FIRST_WRITE: u32 = 0;
const SECOND_WRITE: u32 = 1;
const STALE_READER: u32 = 2;

// ---------------------------------------------------------------------------
// Memory-access tuples of one committed row
// ---------------------------------------------------------------------------

/// The `memory_access` tuples one committed row offers, split by side.
///
/// Fingerprints say *that* the bus moved. Naming the tuples says *which*
/// obligation moved and where it went, which is what turns "the memory
/// argument rejects this" into "this row double-spends `x3` at the first
/// write's access clock".
const MemoryTuples = struct {
    /// `base_alu_imm` emits two access chains — `rs1` then `rd` — and each
    /// contributes one consumed and one emitted tuple.
    const CAPACITY: usize = 4;

    consumed: [CAPACITY][7]QM31 = undefined,
    n_consumed: usize = 0,
    emitted: [CAPACITY][7]QM31 = undefined,
    n_emitted: usize = 0,

    /// The `rs1` chain is emitted before the `rd` chain, which the ordering
    /// assertions in the first test below verify rather than assume.
    fn sourceConsumed(self: *const MemoryTuples) [7]QM31 {
        return self.consumed[0];
    }

    fn sourceEmitted(self: *const MemoryTuples) [7]QM31 {
        return self.emitted[0];
    }

    fn destinationConsumed(self: *const MemoryTuples) [7]QM31 {
        return self.consumed[1];
    }

    fn destinationEmitted(self: *const MemoryTuples) [7]QM31 {
        return self.emitted[1];
    }
};

/// Read the activated `memory_access` entries of `row` out of the AIR's own
/// entry builder — the same call the interaction trace is generated from — and
/// classify each by the sign of its numerator: `accessChain` consumes the
/// predecessor with `-enabler` and emits the successor with `+enabler`.
fn memoryTuples(row: *const committed.Row) !MemoryTuples {
    const list = try opcode_entries.fromMain(harness.FAMILY, row.slice());
    var result = MemoryTuples{};
    for (list.entries[0..list.len]) |emitted| {
        if (emitted.domain != .memory_access) continue;
        if (emitted.numerator.isZero()) continue;
        try std.testing.expectEqual(
            entry_mod.expectedArity(.memory_access),
            emitted.arity,
        );
        if (emitted.numerator.eql(QM31.one())) {
            result.emitted[result.n_emitted] = emitted.values[0..7].*;
            result.n_emitted += 1;
            continue;
        }
        try std.testing.expect(emitted.numerator.eql(QM31.one().neg()));
        result.consumed[result.n_consumed] = emitted.values[0..7].*;
        result.n_consumed += 1;
    }
    try std.testing.expectEqual(MemoryTuples.CAPACITY / 2, result.n_consumed);
    try std.testing.expectEqual(MemoryTuples.CAPACITY / 2, result.n_emitted);
    return result;
}

/// A register access tuple as the bus sees it: address space 0, the register
/// number, the access clock, then the four value limbs.
fn registerTuple(register: u32, clock: u32, value: u32) [7]QM31 {
    return .{
        base(0),
        base(register),
        base(clock),
        base(value & 0xff),
        base((value >> 8) & 0xff),
        base((value >> 16) & 0xff),
        base(value >> 24),
    };
}

fn base(value: u32) QM31 {
    return QM31.fromBase(@import("stwo_core").fields.m31.M31.fromU64(value));
}

fn expectTuple(expected: [7]QM31, actual: [7]QM31) !void {
    try std.testing.expectEqualSlices(QM31, &expected, &actual);
}

/// The fixture guest with the stale-read forgery applied to body row 2.
fn staleReadAttempt(guest: *const committed.Guest, values: *const harness.RowValues) harness.Attempt {
    return .{
        .statement = guest.public.data,
        .witness = harness.override(STALE_READER, values.slice()),
    };
}

// ---------------------------------------------------------------------------
// Row-local evidence
// ---------------------------------------------------------------------------

// Runtime: milliseconds. One nine-instruction run, no proof.
test "malicious prover: the stale register read is row-locally admissible" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    const honest = try guest.honestRow(harness.FAMILY, STALE_READER);
    try committed.expectAccepted(harness.FAMILY, honest.slice());

    // The predecessor the forgery reaches back to is real: body row 0 wrote
    // `x3 = 7` and body row 1 consumed it. A stale read of a value the run
    // never produced would be a different, weaker attack.
    const first_write = try guest.honestRow(harness.FAMILY, FIRST_WRITE);
    try std.testing.expectEqual(
        @as(u32, 7),
        first_write.m31At(harness.RD_NEXT_0).toU32(),
    );

    var forged = honest;
    const values = harness.staleRead();
    forged.apply(values.slice());

    // The forged row consumes the older version at the older clock, re-emits
    // it unchanged (the read-only source binding), and carries the addition
    // through coherently: 7 + 1 = 8 rather than 8 + 1 = 9.
    try std.testing.expectEqual(@as(u32, 7), forged.m31At(harness.RS1_PREV_0).toU32());
    try std.testing.expectEqual(
        access_clock.encode(guest_elf.bodyClock(FIRST_WRITE), .second),
        forged.m31At(harness.RS1_CLOCK_PREV).toU32(),
    );
    try std.testing.expectEqual(@as(u32, 7), forged.m31At(harness.RS1_NEXT_0).toU32());
    try std.testing.expectEqual(@as(u32, 8), forged.m31At(harness.RD_NEXT_0).toU32());
    try std.testing.expectEqual(@as(u32, 8), forged.m31At(harness.RESULT_0).toU32());

    // The load-bearing assertion of the whole attack: every direct constraint
    // of the family vanishes and every activated preprocessed request is in
    // its table. No row-local check rejects this row, so whatever refuses it
    // downstream can only be the global argument.
    try committed.expectAccepted(harness.FAMILY, forged.slice());
}

// Runtime: milliseconds.
test "malicious prover: the stale register read moves the memory-access bus and leaves the state and program buses untouched" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    const honest = try guest.honestRow(harness.FAMILY, STALE_READER);
    var forged = honest;
    const values = harness.staleRead();
    forged.apply(values.slice());

    // The register-state chain is `(pc, clk) -> (pc + 4, clk + 1)` and the
    // program tuple is the fetched word: neither reads a register value, so a
    // forgery of the access chain must leave both untouched. If either moved,
    // the rejection below could be explained by a bus this attack is not about.
    try harness.expectOnlyMemoryBusMoved(&honest, &forged);

    const honest_tuples = try memoryTuples(&honest);
    const forged_tuples = try memoryTuples(&forged);
    const second_write = try guest.honestRow(harness.FAMILY, SECOND_WRITE);
    const second_write_tuples = try memoryTuples(&second_write);

    const first_write_clock = access_clock.encode(guest_elf.bodyClock(FIRST_WRITE), .second);
    const second_write_clock = access_clock.encode(guest_elf.bodyClock(SECOND_WRITE), .second);
    const read_clock = access_clock.encode(guest_elf.bodyClock(STALE_READER), .first);

    // Emission order within the row: the `rs1` chain precedes the `rd` chain.
    // Checked here so the accessors above name what they claim to name.
    try expectTuple(
        registerTuple(SOURCE_REG, second_write_clock, 8),
        honest_tuples.sourceConsumed(),
    );
    try expectTuple(
        registerTuple(SOURCE_REG, read_clock, 8),
        honest_tuples.sourceEmitted(),
    );

    // The honest row links the chain: it consumes exactly what body row 1
    // emitted.
    try expectTuple(second_write_tuples.destinationEmitted(), honest_tuples.sourceConsumed());

    // The forgery double-spends instead: it consumes exactly the tuple body
    // row 1 already consumed, at the same address and the same access clock.
    // That tuple is now taken twice and emitted once, and body row 1's own
    // emission is orphaned — the two halves of the non-cancellation.
    try expectTuple(
        registerTuple(SOURCE_REG, first_write_clock, 7),
        forged_tuples.sourceConsumed(),
    );
    try expectTuple(second_write_tuples.sourceConsumed(), forged_tuples.sourceConsumed());
    try expectTuple(
        registerTuple(SOURCE_REG, read_clock, 7),
        forged_tuples.sourceEmitted(),
    );

    // The destination access keeps its predecessor and moves only the written
    // word, so the forgery is a coherent re-derivation and not a second,
    // independent disturbance of the same bus.
    try expectTuple(honest_tuples.destinationConsumed(), forged_tuples.destinationConsumed());
    try std.testing.expect(!std.mem.eql(
        u8,
        std.mem.sliceAsBytes(&honest_tuples.destinationEmitted()),
        std.mem.sliceAsBytes(&forged_tuples.destinationEmitted()),
    ));
}

// ---------------------------------------------------------------------------
// The production transaction
// ---------------------------------------------------------------------------

// Runtime: about 12 s. One complete proof of the forged witness plus the
// verification that must refuse it.
test "malicious prover: the stale register read proves and loses global closure at verification" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    // Installed before lookup ingestion, so the whole transaction — main
    // trace, multiplicities, interaction trace, challenges — derives from the
    // forged witness. Rejected at the last possible stage, by the verifier's
    // global LogUp cancellation, because nothing earlier can see a row this
    // self-consistent.
    const values = harness.staleRead();
    try harness.expectRejected(
        &guest,
        staleReadAttempt(&guest, &values),
        .verification,
        error.LogupSumNonZero,
    );
}

// ---------------------------------------------------------------------------
// Which relation domain fails to close
// ---------------------------------------------------------------------------

/// Per-domain closure of one production run: the committed sum of every
/// component against the public boundary of the same relation.
const DomainClosure = struct {
    totals: [entry_mod.DOMAIN_COUNT]QM31,

    fn of(diagnostic: *const prover_mod.RelationDiagnostic) DomainClosure {
        var result = DomainClosure{ .totals = undefined };
        for (0..entry_mod.DOMAIN_COUNT) |index| {
            result.totals[index] = diagnostic.bundle.aggregate.domain_sums[index]
                .add(diagnostic.bundle.public.domains[index]);
        }
        return result;
    }
};

/// Re-run the same production transaction in `.relation_diagnostic` mode.
///
/// Identical up to Tree 2 — same witness, same mutation hook, same ingestion —
/// and it stops before proof assembly, exposing the per-component and
/// per-domain relation sums the proof reduces to a single scalar. The
/// challenges come from a fresh channel by design (see
/// `prover/interaction_trace.zig`), which is what makes the sums comparable
/// across runs; this is an attribution instrument, and the rejection itself is
/// pinned on the real `.prove` path above.
fn diagnose(
    guest: *const committed.Guest,
    mutation: ?committed.Mutation,
) !prover_mod.RelationDiagnostic {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    return orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        riscv_cpu.CpuProverEngine,
        .relation_diagnostic,
        guest.allocator,
        committed.PCS_CONFIG,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        null,
        guest.public.data,
        &channel,
        mutation,
        null,
    );
}

// Runtime: about 25 s. Two diagnostic runs of the fixture guest, each stopping
// before proof assembly.
test "malicious prover: only the memory-access relation fails to close over the stale read" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    // The instrument's own baseline. Without it, "only `memory_access` fails"
    // would also be satisfied by an instrument that reports a non-zero
    // `memory_access` sum on every run.
    const honest = try diagnose(&guest, null);
    try honest.bundle.validate();
    const honest_closure = DomainClosure.of(&honest);
    for (honest_closure.totals) |total| try std.testing.expect(total.isZero());

    const values = harness.staleRead();
    const forged = try diagnose(&guest, harness.override(STALE_READER, values.slice()));
    const forged_closure = DomainClosure.of(&forged);
    for (forged_closure.totals, 0..) |total, index| {
        const domain: entry_mod.Domain = @enumFromInt(index);
        if (domain == .memory_access) {
            try std.testing.expect(!total.isZero());
            continue;
        }
        if (!total.isZero()) {
            std.debug.print(
                "stale read disturbed the {s} relation as well\n",
                .{@tagName(domain)},
            );
            return error.TestUnexpectedResult;
        }
    }

    // The bundle's own consistency check reaches the same verdict by its own
    // route: every component claim still matches its recomputation from the
    // committed tuples — the forged witness is internally consistent — and the
    // first thing that does not hold is one relation domain's balance.
    try std.testing.expectError(
        error.UnbalancedRelationDomain,
        forged.bundle.validate(),
    );
}
