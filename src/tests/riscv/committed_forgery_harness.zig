//! End-to-end committed-trace forgery harness: run a guest, prove it honestly,
//! verify, then re-prove with one row overridden and require rejection.
//!
//! A row-local test says "the AIR would reject this row". It does not say the
//! row can be *reached*: a forgery must survive committing the trace, the
//! interaction argument, and the verifier's global LogUp closure, and a
//! constraint can be row-locally sound while the committed pipeline never
//! evaluates it. So each closed under-constraint needs one test that proves the
//! forged row into a real proof and watches production reject it.
//!
//! Two halves matter equally.
//!
//!  - The HONEST half must pass. A guest that cannot be proven at all would
//!    satisfy "the forgery is rejected" vacuously, so `Guest.proveAndVerify`
//!    runs first and its failure is the harness's failure, not the forgery's.
//!  - The FORGED half must be rejected by the prover's own constraint check or
//!    by verification. Both are acceptable outcomes: an unsatisfied direct
//!    constraint aborts proving with `error.ConstraintsNotSatisfied`, while an
//!    absent lookup tuple survives proving and breaks verification.
//!
//! Attribution is separate and row-local, because "rejected" alone is not
//! evidence for the constraint under test. `attribute` reports *which* direct
//! constraint index or *which* lookup domain rejects a row, so a test can pin
//! the reason and fail if a sibling check happens to catch the forgery first.
//!
//! Runtime: about eleven seconds per end-to-end case on an M-series CPU — two
//! proofs of a nine-to-twelve instruction guest at three FRI queries. Row-local
//! attribution is milliseconds.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;

const riscv_cpu = @import("../../integrations/riscv_cpu/mod.zig");
const orchestration = @import("../../frontends/riscv/prover/orchestration.zig");
const witness_hook = @import("../../frontends/riscv/prover/test_witness_hook.zig");
const semantic_eval = @import("../../frontends/riscv/air/semantic_eval.zig");
const entry_mod = @import("../../frontends/riscv/air/lookups/entry.zig");
const opcode_entries = @import("../../frontends/riscv/air/lookups/opcode_entries.zig");
const public_values = @import("../../frontends/riscv/diagnostics/public_values.zig");
const runner = @import("../../frontends/riscv/runner/mod.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");

const guest_elf = @import("guest_elf_fixture.zig");
const row_admissibility = @import("row_admissibility.zig");

pub const OpcodeFamily = trace_mod.OpcodeFamily;
pub const Spec = guest_elf.Spec;
pub const ColumnValue = witness_hook.ColumnValue;
pub const RowOverride = witness_hook.RowOverride;
pub const Target = witness_hook.Target;
pub const Mutation = orchestration.TestWitnessMutation;
pub const TraceDump = orchestration.TestTraceDump;
pub const TableRejection = row_admissibility.TableRejection;
pub const Domain = entry_mod.Domain;

/// Smallest honest configuration: no proof of work, one blowup, three queries.
/// Soundness of the proof system is not what these tests measure, and the
/// honest half is run once per case, so the cheapest sound-shaped parameters
/// are the right ones.
pub const PCS_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

/// One committed opcode-family row as secure-field cells.
pub const Row = struct {
    cells: [trace_mod.MAX_FAMILY_COLUMNS]QM31,
    n_columns: usize,

    pub fn slice(self: *const Row) []const QM31 {
        return self.cells[0..self.n_columns];
    }

    /// Assign absolute values, reducing through `M31.fromU64` exactly as
    /// `test_witness_hook.overrideRow` does, so the row this returns and the
    /// row the prover commits are the same field elements rather than two
    /// roundings of one integer.
    pub fn apply(self: *Row, values: []const ColumnValue) void {
        for (values) |value| {
            self.cells[value.column] = QM31.fromBase(M31.fromU64(value.value));
        }
    }

    pub fn m31At(self: *const Row, column: usize) M31 {
        return self.cells[column].tryIntoM31() catch unreachable;
    }
};

/// One guest: its ELF, its run, and the public statement derived from that run.
///
/// The caller supplies only the instruction body. Every field of `PublicData`
/// is derived here through `diagnostics/public_values.derive`, which reads the
/// completed run: initial and final pc, the step clock, initial and final
/// registers, `reg_last_clock`, the completion record, the program and RW
/// Merkle roots, and the whole `io_entries` block. There is no `PublicData`
/// field for a caller to get wrong, and no caller-supplied input: the fixture
/// owns the input word its prologue reads.
pub const Guest = struct {
    allocator: std.mem.Allocator,
    elf: []u8,
    run: runner.RunResult,
    public: public_values.OwnedPublicData,

    pub fn init(allocator: std.mem.Allocator, spec: Spec) !Guest {
        const elf = try guest_elf.build(allocator, spec);
        errdefer allocator.free(elf);
        var run = try runner.runWithInput(
            allocator,
            elf,
            &guest_elf.INPUT,
            guest_elf.maxSteps(spec),
        );
        errdefer run.deinit();
        // A guest that stopped for any other reason has a different public
        // completion record, so every downstream expectation would be about a
        // program the caller did not write.
        if (run.completion_reason != .halt_flag) return error.GuestDidNotHalt;
        const public = try public_values.derive(allocator, &run);
        return .{ .allocator = allocator, .elf = elf, .run = run, .public = public };
    }

    pub fn deinit(self: *Guest) void {
        self.public.deinit(self.allocator);
        self.run.deinit();
        self.allocator.free(self.elf);
        self.* = undefined;
    }

    /// How many rows of `family` the run retired.
    pub fn familyRowCount(self: *const Guest, family: OpcodeFamily) !usize {
        var counts = try self.run.execution_trace.groupByOpcodeFamily(self.allocator);
        return counts.get(family);
    }

    /// The honest committed row `logical_row` of `family`, read out of the
    /// witness generator rather than transcribed, so a witness-generation
    /// change moves the baseline instead of desynchronising it from the test.
    ///
    /// `logical_row` is the family-relative index in execution order, which is
    /// exactly the `logical_row` a `RowOverride` names.
    pub fn honestRow(
        self: *const Guest,
        family: OpcodeFamily,
        logical_row: usize,
    ) !Row {
        const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, logical_row + 1));
        var columns = try self.run.execution_trace.columnsForFamily(
            self.allocator,
            family,
            log_size,
        );
        defer columns.deinit(self.allocator);
        if (logical_row >= columns.n_real_rows) return error.NoSuchCommittedRow;

        var row = Row{ .cells = undefined, .n_columns = columns.n_columns };
        for (0..columns.n_columns) |column| {
            row.cells[column] = QM31.fromBase(columns.columns[column][logical_row]);
        }
        return row;
    }

    /// Prove and verify the unmutated guest. Failure here is a broken fixture,
    /// not evidence about any forgery.
    pub fn proveAndVerify(self: *const Guest) !void {
        const output = try riscv_cpu.proveRiscVWithPublicData(
            self.allocator,
            PCS_CONFIG,
            &self.run.execution_trace,
            &self.run.state_chain_tracker,
            &self.run.rw_memory,
            null,
            self.public.data,
        );
        defer output.deinitAfterProofMoved(self.allocator);
        try riscv_cpu.verifyRiscV(
            self.allocator,
            PCS_CONFIG,
            output.statement,
            output.proof,
            output.interaction_claim,
        );
    }

    /// Prove the guest with `mutation` applied and require that proving or
    /// verification rejects it, without saying which.
    pub fn expectRejected(self: *const Guest, mutation: Mutation) !void {
        return self.expectRejectedAt(mutation, .any);
    }

    /// Prove the guest with `mutation` applied, exporting the committed opcode
    /// trace, the relation challenges and the interaction claims of that run
    /// into `dump`, and report how the pipeline decided the run.
    ///
    /// The export happens inside the run, before the proof is assembled, so a
    /// forgery a direct constraint refuses is still exported. That is the point:
    /// an external checker must be able to read the witness the prover
    /// *committed*, not only the subset that survived to a proof.
    pub fn proveCapturing(
        self: *const Guest,
        mutation: ?Mutation,
        dump: *TraceDump,
    ) !Outcome {
        var channel = riscv_cpu.CpuProverEngine.Channel{};
        const output = orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
            riscv_cpu.CpuProverEngine,
            .prove,
            self.allocator,
            PCS_CONFIG,
            &self.run.execution_trace,
            &self.run.state_chain_tracker,
            &self.run.rw_memory,
            null,
            self.public.data,
            &channel,
            mutation,
            dump,
        ) catch |err| {
            try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
            return .rejected_proving;
        };
        defer output.deinitAfterProofMoved(self.allocator);
        riscv_cpu.verifyRiscV(
            self.allocator,
            PCS_CONFIG,
            output.statement,
            output.proof,
            output.interaction_claim,
        ) catch return .rejected_verification;
        return .verified;
    }

    /// Prove the guest with `mutation` applied and require rejection at
    /// `stage`.
    ///
    /// The stage is the one end-to-end attribution the committed pipeline
    /// offers. A forgery that breaks a direct constraint cannot produce a proof
    /// at all; a forgery that is row-locally coherent must produce a proof and
    /// lose at verification. Pinning the stage therefore distinguishes the two
    /// kinds of fix: delete a lookup request whose absence makes the row
    /// admissible and a `.verification` expectation fails, because the proof
    /// verifies.
    pub fn expectRejectedAt(
        self: *const Guest,
        mutation: Mutation,
        stage: RejectionStage,
    ) !void {
        var channel = riscv_cpu.CpuProverEngine.Channel{};
        const output = orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
            riscv_cpu.CpuProverEngine,
            .prove,
            self.allocator,
            PCS_CONFIG,
            &self.run.execution_trace,
            &self.run.state_chain_tracker,
            &self.run.rw_memory,
            null,
            self.public.data,
            &channel,
            mutation,
            null,
        ) catch |err| {
            // A direct constraint that does not vanish stops the prover before
            // a proof exists; that is a rejection, not a harness failure.
            try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
            if (stage == .verification) {
                std.debug.print(
                    "expected a verification rejection; proving already refused the row\n",
                    .{},
                );
                return error.TestUnexpectedResult;
            }
            return;
        };
        if (stage == .prover_constraints) {
            // Nothing consumes the proof on this path, so it is released whole rather
            // than through the after-verification form; otherwise a failed expectation
            // reports a leak on top of the mismatch it is trying to show.
            var produced = output;
            produced.deinit(self.allocator);
            std.debug.print(
                "expected proving to refuse the row; it produced a proof\n",
                .{},
            );
            return error.TestUnexpectedResult;
        }
        // Verification takes ownership of the proof on both its success and its
        // failure paths, so only the boxed claim is left to release here.
        defer output.deinitAfterProofMoved(self.allocator);
        try std.testing.expect(std.meta.isError(riscv_cpu.verifyRiscV(
            self.allocator,
            PCS_CONFIG,
            output.statement,
            output.proof,
            output.interaction_claim,
        )));
    }
};

/// How the committed pipeline decided one proving run. `expectRejectedAt`
/// asserts against `RejectionStage`; `proveCapturing` reports this instead,
/// because an export run must be able to say "verified" as an ordinary result.
pub const Outcome = enum { verified, rejected_proving, rejected_verification };

/// Where in the pipeline a forged row must be refused.
pub const RejectionStage = enum {
    /// Either half may reject.
    any,
    /// A direct constraint must not vanish, so proving fails with
    /// `error.ConstraintsNotSatisfied` and no proof exists.
    prover_constraints,
    /// Every direct constraint vanishes, so proving must succeed and
    /// verification must fail. The end-to-end shape of a fix that lives in a
    /// lookup request or in a bus tuple.
    verification,
};

/// The whole end-to-end obligation in one call: the guest proves and verifies
/// honestly, and the same guest with `override` applied does not.
///
/// `override.values` is borrowed for the duration of the call.
pub fn expectHonestProofAndForgedRejection(
    allocator: std.mem.Allocator,
    spec: Spec,
    override: RowOverride,
    stage: RejectionStage,
) !void {
    var guest = try Guest.init(allocator, spec);
    defer guest.deinit();
    try guest.proveAndVerify();
    try guest.expectRejectedAt(.{ .main_row = override }, stage);
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

/// Which direct constraints of a family a row fails.
pub const ConstraintFailure = struct {
    /// Index of the first non-vanishing constraint, in `semantic_eval` order.
    index: usize,
    /// How many constraints fail. A test that means to exercise one constraint
    /// wants this to be one; more than one says the forged row is incoherent
    /// somewhere else too.
    count: usize,
    /// How many constraints the family evaluates, for a readable failure.
    total: usize,
};

/// Why the AIR rejects a row, or that it does not.
pub const Attribution = union(enum) {
    accepted,
    /// A direct constraint does not vanish, so the prover rejects the row
    /// before a proof exists.
    constraints: ConstraintFailure,
    /// Every direct constraint vanishes and an activated lookup request is
    /// absent from its preprocessed table, so the forgery survives proving and
    /// breaks the interaction argument.
    lookup: TableRejection,
};

/// Decide `columns` on the direct constraints and on preprocessed lookup
/// membership, reporting which of the two rejected and exactly where.
pub fn attribute(family: OpcodeFamily, columns: []const QM31) !Attribution {
    const evaluation = try semantic_eval.evaluate(family, columns, QM31.one());
    var failure = ConstraintFailure{ .index = 0, .count = 0, .total = evaluation.len };
    for (evaluation.values[0..evaluation.len], 0..) |value, index| {
        if (value.isZero()) continue;
        if (failure.count == 0) failure.index = index;
        failure.count += 1;
    }
    if (failure.count != 0) return .{ .constraints = failure };

    return switch (try row_admissibility.verdict(family, columns)) {
        .accepted => .accepted,
        // `verdict` re-evaluates the same direct constraints, which just
        // vanished, so this arm is unreachable rather than a case to report.
        .direct_constraints => unreachable,
        .table => |rejection| .{ .lookup = rejection },
    };
}

/// Assert the row is admissible: every direct constraint vanishes and every
/// activated request is in its table. The honest baseline of a forgery test.
pub fn expectAccepted(family: OpcodeFamily, columns: []const QM31) !void {
    switch (try attribute(family, columns)) {
        .accepted => {},
        .constraints => |failure| {
            std.debug.print(
                "expected an admissible row; constraint {d} of {d} does not vanish\n",
                .{ failure.index, failure.total },
            );
            return error.TestUnexpectedResult;
        },
        .lookup => |rejection| {
            std.debug.print(
                "expected an admissible row; request {d} on {s} is out of table\n",
                .{ rejection.index, @tagName(rejection.domain) },
            );
            return error.TestUnexpectedResult;
        },
    }
}

/// Assert the row fails constraint `index` and no other direct constraint.
///
/// This is the attribution shape for a fix that lives in a direct constraint:
/// "rejected" is not evidence unless the rejection is the constraint under
/// test, and a second failing constraint means the forged row is incoherent
/// for an unrelated reason.
pub fn expectOnlyConstraint(
    family: OpcodeFamily,
    columns: []const QM31,
    index: usize,
) !void {
    switch (try attribute(family, columns)) {
        .constraints => |failure| {
            try std.testing.expectEqual(index, failure.index);
            try std.testing.expectEqual(@as(usize, 1), failure.count);
        },
        .accepted => {
            std.debug.print("expected constraint {d} to fail; the row is admissible\n", .{index});
            return error.TestUnexpectedResult;
        },
        .lookup => |rejection| {
            std.debug.print(
                "expected constraint {d} to fail; request {d} on {s} rejected instead\n",
                .{ index, rejection.index, @tagName(rejection.domain) },
            );
            return error.TestUnexpectedResult;
        },
    }
}

/// Fingerprint of everything the row offers to one relation: each activated
/// entry's numerator and tuple, in emission order.
///
/// Two rows with equal fingerprints on a bus ask that bus for exactly the same
/// thing, so the bus cannot tell them apart. That is the question an end-to-end
/// forgery test has to answer before claiming its rejection is attributable to
/// a preprocessed table: if the forged row's `memory_access` fingerprint moved,
/// the global memory argument rejects it whatever the table does, and the
/// end-to-end half proves reachability rather than attribution.
pub fn busFingerprint(
    family: OpcodeFamily,
    columns: []const QM31,
    domain: Domain,
) !u64 {
    const list = try opcode_entries.fromMain(family, columns);
    var hasher = std.hash.Wyhash.init(0);
    for (list.entries[0..list.len]) |emitted| {
        if (emitted.domain != domain) continue;
        if (emitted.numerator.isZero()) continue;
        hasher.update(std.mem.asBytes(&emitted.numerator));
        hasher.update(std.mem.sliceAsBytes(emitted.values[0..emitted.arity]));
    }
    return hasher.final();
}

/// Assert every direct constraint vanishes and the first out-of-table request
/// is on `domain`, returning it so the caller can pin the request's position
/// and tuple.
///
/// This is the attribution shape for a fix that lives in a lookup request. The
/// all-zero direct evaluation is the load-bearing half: it says the forged row
/// is self-consistent, so the rejection is not a carry chain, a read-only
/// access binding or a destination write in disguise.
pub fn expectOnlyLookup(
    family: OpcodeFamily,
    columns: []const QM31,
    domain: Domain,
) !TableRejection {
    switch (try attribute(family, columns)) {
        .lookup => |rejection| {
            try std.testing.expectEqual(domain, rejection.domain);
            return rejection;
        },
        .accepted => {
            std.debug.print(
                "expected a {s} rejection; the row is admissible\n",
                .{@tagName(domain)},
            );
            return error.TestUnexpectedResult;
        },
        .constraints => |failure| {
            std.debug.print(
                "expected a {s} rejection; constraint {d} of {d} does not vanish\n",
                .{ @tagName(domain), failure.index, failure.total },
            );
            return error.TestUnexpectedResult;
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const layout = @import("committed_row_layout.zig");

/// `ADDI x10, x0, 7`, whose committed row is a `base_alu_imm` row.
const ADDI_X10_7: u32 = 0x0070_0513;

// Runtime: milliseconds. One nine-instruction run, no proof.
test "forgery harness: the honest row of a body instruction is admissible where the fixture says" {
    var guest = try Guest.init(std.testing.allocator, .{ .body = &.{ADDI_X10_7} });
    defer guest.deinit();

    // The epilogue retires two `ADDI`s of its own, so the body's row is only
    // unambiguous because it precedes them: logical row 0 of the family.
    try std.testing.expectEqual(@as(usize, 3), try guest.familyRowCount(.base_alu_imm));
    const row = try guest.honestRow(.base_alu_imm, 0);
    try expectAccepted(.base_alu_imm, row.slice());
    try std.testing.expectEqual(
        M31.fromCanonical(guest_elf.bodyPc(0)),
        row.m31At(semantic_eval.pcColumn(.base_alu_imm)),
    );
    try std.testing.expectEqual(
        M31.fromCanonical(guest_elf.bodyClock(0)),
        row.m31At(semantic_eval.clockColumn(.base_alu_imm)),
    );
}

// Runtime: milliseconds.
test "forgery harness: attribution separates a broken constraint from a missing table entry" {
    var guest = try Guest.init(std.testing.allocator, .{ .body = &.{ADDI_X10_7} });
    defer guest.deinit();
    const honest = try guest.honestRow(.base_alu_imm, 0);

    // Raising the low result limb alone breaks the addition itself, so the
    // rejection is a direct constraint and `expectOnlyLookup` must refuse it.
    var broken = honest;
    broken.apply(&.{.{
        .column = @intCast(layout.nextLimbColumn(.base_alu_imm, 0, 0)),
        .value = 9,
    }});
    switch (try attribute(.base_alu_imm, broken.slice())) {
        .constraints => |failure| try std.testing.expect(failure.count >= 1),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(
        error.TestUnexpectedResult,
        expectOnlyLookup(.base_alu_imm, broken.slice(), .range_check_8_8_4),
    );

    // The honest row is admissible, so neither attribution helper accepts it.
    try std.testing.expectError(
        error.TestUnexpectedResult,
        expectOnlyConstraint(.base_alu_imm, honest.slice(), 0),
    );
}
