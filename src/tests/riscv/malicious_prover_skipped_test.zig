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
//! What does catch the shortened trace is the register-access chain.
//! `air/opcode_memory.zig` `deriveRegisterBoundary` replays every row's register
//! accesses and requires each one to continue the boundary it has built so far;
//! dropping a retirement leaves the next reader of that register naming a
//! previous clock and value nobody produced, so it returns
//! `error.InvalidRegisterAccessChain`. `prover.zig:66` runs it on the entry
//! point that derives the statement from the trace, which is exactly the
//! "recompute the geometry" prover. The skip is therefore an access-chain
//! violation, not a placement violation -- a different acceptance criterion,
//! owned by the bus-soundness surface.
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

/// Smallest domain `source_ingest` admits (`size < 16` is `InvalidDomainSize`),
/// which is also the domain the production shard of this fixture uses.
const SHORT_LOG_SIZE: u32 = 4;

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
test "malicious prover: a structurally shortened trace loses on the access chain, not on placement" {
    const allocator = std.testing.allocator;
    var guest = try committed.Guest.init(allocator, harness.SPEC);
    defer guest.deinit();
    var short = try shortenedTrace(allocator, &guest.run.execution_trace);
    defer short.deinit();

    // The declared geometry shrank with the trace instead of keeping a hole:
    // `n_real_rows` is the count of rows actually written, and the statement's
    // shard length comes from the same row list.
    var columns = try short.columnsForFamily(allocator, harness.FAMILY, SHORT_LOG_SIZE);
    defer columns.deinit(allocator);
    try std.testing.expectEqual(harness.FAMILY_ROWS - 1, columns.n_real_rows);

    // So over the whole shard domain, under the `is_active` that the prover and
    // the verifier both derive from that geometry, every constraint vanishes --
    // the placement constraint included -- and no real row is inactive. The
    // skip would survive both `source_ingest` and composition.
    const size = @as(usize, 1) << @intCast(SHORT_LOG_SIZE);
    for (0..size) |logical_row| {
        var cells: [trace_mod.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (
            cells[0..columns.n_columns],
            columns.columns[0..columns.n_columns],
        ) |*cell, column| {
            cell.* = QM31.fromBase(column[logical_row]);
        }
        const real = logical_row < columns.n_real_rows;
        const evaluation = try semantic_eval.evaluate(
            harness.FAMILY,
            cells[0..columns.n_columns],
            if (real) QM31.one() else QM31.zero(),
        );
        try std.testing.expect(evaluation.allZero());
        try std.testing.expectEqual(real, try emitsActiveRequest(cells[0..columns.n_columns]));
    }

    // What refuses it instead, on the entry point that recomputes the statement
    // from the trace (`prover.zig` `proveRiscVTraceOnlyNoPublicIoUsingChannel`): the
    // register-access chain no longer closes, because the next reader of the
    // skipped instruction's destination names a previous clock and value that
    // no retirement produced. The honest rows are the control -- the same
    // derivation accepts them, so the rejection is the omission and not the
    // fixture.
    _ = try opcode_memory.deriveRegisterBoundary(guest.run.execution_trace.rows.items);
    try std.testing.expectError(
        error.InvalidRegisterAccessChain,
        opcode_memory.deriveRegisterBoundary(short.rows.items),
    );
}
