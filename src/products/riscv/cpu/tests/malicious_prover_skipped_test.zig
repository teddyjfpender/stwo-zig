//! Malicious prover, skipped instruction: an active opcode row committed as
//! all-zero padding.
//!
//! The attack is the cheapest thing a prover can do to a step it does not want
//! on the record: retire the instruction in the run, then commit its row as
//! padding, so the step's register write, its program access and its
//! state-chain link never reach any bus. It is not a post-hoc mutation of an
//! honest proof. The padding is installed by the witness hook in
//! `prover/main_trace.zig`, between opcode-witness generation and
//! `lookup_sources.ingest`, so the lookup multiplicities, the committed Tree 1
//! and the Tree 2 interactions all derive from the padded witness. There is no
//! honest artefact left for it to disagree with.
//!
//! ## What is pinned, and why it is not what the issue predicted
//!
//! The issue's acceptance criterion reads "an active opcode row replaced by
//! padding is rejected by the active-row placement constraint", which predicts
//! `prover_constraints` / `error.ConstraintsNotSatisfied`. Production refuses
//! the request strictly earlier, at `.precommit_ingestion` with
//! `error.InactiveRealRow`, raised by `air/lookups/tables/source_ingest.zig`
//! (`if (row < shard.n_real_rows and !active) return error.InactiveRealRow;`)
//! before any table is committed and therefore before any composition
//! polynomial exists. That is the honest answer, and it is what the end-to-end
//! test pins. Note also that the prover's own `validateDirectSemantics` cannot
//! see this forgery: `prover/opcode_trace.zig` runs it on the generated witness,
//! before the hook rewrites the row.
//!
//! A stage on its own would understate the criterion, so the first two tests
//! below are a pair and the pairing is the argument:
//!
//!  - row-locally, the active-row placement constraint is the *unique* direct
//!    constraint the padded row fails, so the criterion's claim about the AIR
//!    holds exactly as stated; and
//!  - end-to-end, production never gets that far, because structural admission
//!    of the committed rows rejects the padding first.
//!
//! Shipping either half alone would be misleading: the row-local half would not
//! show the forgery is reachable, and the end-to-end half would not show which
//! constraint owns the criterion. Both controls -- the honest row is admissible
//! and ingestion-active, the padded row asks nothing of any bus -- are there so
//! neither half can pass because the pipeline refuses everything.
//!
//! ## The structurally shortened trace (the deeper threat model)
//!
//! The handoff also asked whether a prover could *genuinely* omit an
//! instruction, recompute the geometry, survive ingestion, and be caught by the
//! placement constraint at composition instead. It cannot, and the third test
//! pins both halves of why.
//!
//! Placement cannot fire, structurally. `runner/trace.zig` `columnsForFamily`
//! packs a family's rows contiguously from index 0 and reports `n_real_rows` as
//! the count it wrote; `prover/opcode_trace.zig` derives each shard's
//! `n_real_rows` from the same row list, and `prover/statement_geometry.zig`
//! derives the shard lengths from `groupByOpcodeFamily` over that same list. So
//! `is_active` and the committed `row.active()` are two readings of one row
//! list: omitting an instruction shortens the declared geometry instead of
//! leaving a hole in it, every real row stays active, and `active() - is_active`
//! vanishes by construction. The only way to desynchronise the two is a
//! cell-level forgery inside the real region -- this file's attack, which
//! ingestion refuses first. The composition-time placement rejection is
//! therefore defence in depth behind `source_ingest`, not a reachable
//! production verdict.
//!
//! What catches the shortened trace first is the authenticated retirement
//! clock: `Trace.append` refuses the gap left by the omitted instruction. A
//! direct audit of the remaining rows also proves the underlying register
//! access chain does not close. The skip is therefore a clock/access-chain
//! violation, not a placement violation.
//!
//! The one case this file deliberately does not construct is a shortened trace
//! carried on the public-data entry point with a *recomputed* statement, which
//! bypasses `prover.zig:66`. There is no production surface for it: a statement
//! is derived by `diagnostics/public_values.derive` from a `runner.RunResult`,
//! and a `RunResult` is only ever produced by `runner/mod.zig` executing an ELF
//! faithfully, so a self-consistent statement for a trace the runner did not
//! produce cannot be built through shipped code.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const opcode_entries = @import("stwo_riscv_frontend").air.lookups.opcode_entries;
const opcode_memory = @import("stwo_riscv_frontend").air.opcode_memory;
const semantic_eval = @import("stwo_riscv_frontend").air.semantic_eval;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;

const committed = @import("committed_forgery_harness.zig");
const guest_elf = @import("guest_elf_fixture.zig");
const harness = @import("malicious_prover_harness.zig");

/// Logical row of the family the prover declines to retire: the fixture's first
/// body instruction, `ADDI x3, x0, 7`. The body's rows precede the epilogue's
/// two `ADDI`s in the family, so this names one specific instruction.
const SKIPPED_ROW: u32 = 0;

/// The active-row placement constraint's index in `semantic_eval` order.
///
/// `evaluateModule` appends `placementConstraint` after the family's own
/// `N_CONSTRAINTS`, so the placement constraint is always the family's last.
fn placementConstraintIndex() usize {
    return semantic_eval.constraintCount(harness.FAMILY) - 1;
}

/// Ingestion's own notion of an active row, recomputed row-locally.
///
/// `source_ingest.scanShard` calls a committed row active when any entry it
/// emits carries a non-zero numerator, and refuses a row below `n_real_rows`
/// that is not. Recomputing that predicate here is what lets the end-to-end
/// `error.InactiveRealRow` be attributed to the padding itself rather than to
/// some other property of the run.
fn emitsActiveRequest(columns: []const QM31) !bool {
    const list = try opcode_entries.fromMain(harness.FAMILY, columns);
    for (list.entries[0..list.len]) |emitted| {
        if (!emitted.numerator.isZero()) return true;
    }
    return false;
}

/// The fixture's retirement sequence with the skipped instruction genuinely
/// absent, as a prover that declines to retire it would present.
///
/// The caller owns the returned trace.
fn shortenedTrace(
    allocator: std.mem.Allocator,
    honest: *const trace_mod.Trace,
) !trace_mod.Trace {
    var short = trace_mod.Trace.init(allocator);
    errdefer short.deinit();
    short.initial_pc = honest.initial_pc;
    short.final_pc = honest.final_pc;
    var dropped: usize = 0;
    for (honest.rows.items) |row| {
        if (row.pc == guest_elf.bodyPc(0)) {
            dropped += 1;
            continue;
        }
        try short.append(row);
    }
    // The fixture is straight-line, so the skipped instruction's pc identifies
    // exactly one retirement.
    if (dropped != 1) return error.TestUnexpectedResult;
    return short;
}

// Runtime: milliseconds. One run of the fixture guest, no proof.
test "malicious prover: the active-row placement constraint alone rejects a padded opcode row" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();
    try std.testing.expectEqual(harness.FAMILY_ROWS, try guest.familyRowCount(harness.FAMILY));

    // Control. Without it, "the padded row is rejected" would also be satisfied
    // by a pipeline that refuses every row of this family, and the end-to-end
    // `InactiveRealRow` would also be satisfied by a fixture whose honest rows
    // are inactive to begin with.
    const honest = try guest.honestRow(harness.FAMILY, SKIPPED_ROW);
    try committed.expectAccepted(harness.FAMILY, honest.slice());
    try std.testing.expect(try emitsActiveRequest(honest.slice()));

    var padded = honest;
    const padding = harness.skippedRow(honest.n_columns);
    padded.apply(padding.slice());
    for (padded.slice()) |cell| try std.testing.expect(cell.isZero());

    // The acceptance criterion, row-locally: the active-row placement
    // constraint is the unique direct constraint the padded row fails. A second
    // failing constraint would mean the criterion is being satisfied by some
    // incidental incoherence of the all-zero row instead.
    try committed.expectOnlyConstraint(
        harness.FAMILY,
        padded.slice(),
        placementConstraintIndex(),
    );

    // And the padded row asks nothing of any bus, which is exactly the
    // condition `source_ingest` refuses below `n_real_rows` -- the reason the
    // end-to-end verdict below is an ingestion verdict and not a composition
    // one.
    try std.testing.expect(!(try emitsActiveRequest(padded.slice())));
}

// Runtime: seconds. One proving attempt, stopped before Tree 1 is committed.
test "malicious prover: a skipped instruction is refused at lookup-source ingestion" {
    var guest = try committed.Guest.init(std.testing.allocator, harness.SPEC);
    defer guest.deinit();

    const honest = try guest.honestRow(harness.FAMILY, SKIPPED_ROW);
    const padding = harness.skippedRow(honest.n_columns);
    try harness.expectRejected(
        &guest,
        .{
            .statement = guest.public.data,
            .witness = harness.override(SKIPPED_ROW, padding.slice()),
        },
        .precommit_ingestion,
        error.InactiveRealRow,
    );
}

// Runtime: milliseconds. One run of the fixture guest, no proof.
test "malicious prover: a structurally shortened trace loses on clock and access chains, not placement" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();

    // Production trace custody rejects the omitted retirement before a
    // shortened trace can be admitted or committed.
    try std.testing.expectError(
        error.InstructionClockMismatch,
        shortenedTrace(allocator, &guest.run.execution_trace),
    );

    // The remaining raw rows independently fail the register-access chain.
    const honest_rows = guest.run.execution_trace.rows.items;
    const short_rows = try allocator.alloc(trace_mod.TraceRow, honest_rows.len - 1);
    defer allocator.free(short_rows);
    var destination: usize = 0;
    for (honest_rows) |row| {
        if (row.pc == guest_elf.bodyPc(0)) continue;
        short_rows[destination] = row;
        destination += 1;
    }
    try std.testing.expectEqual(short_rows.len, destination);
    _ = try opcode_memory.deriveRegisterBoundary(guest.run.execution_trace.rows.items);
    try std.testing.expectError(
        error.InvalidRegisterAccessChain,
        opcode_memory.deriveRegisterBoundary(short_rows),
    );
}
