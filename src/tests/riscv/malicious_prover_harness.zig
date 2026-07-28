//! Production-path malicious-prover harness.
//!
//! Ordinary execution agreement starts with an honest runner trace.  That is
//! necessary, but it cannot answer whether an adversarial prover can choose a
//! different witness or public statement and still obtain an accepted proof.
//! This harness enters the real proving transaction at those two adversarial
//! boundaries and records the exact stage that refuses the attempt:
//!
//!  - precommit ingestion, before the lookup sources exist;
//!  - admission, before any transcript event;
//!  - the prover's direct-constraint check, before a proof exists; or
//!  - verification, after a proof was produced from the malicious witness.
//!
//! The four attacks are deliberately not mutations of an honest proof.
//! Skipped and stale rows are installed before lookup ingestion, so Tree 1,
//! lookup multiplicities and Tree 2 all derive from the same forged witness.
//! Forged output and completion values enter as the prover's original public
//! statement, before Fiat-Shamir challenges are drawn.  A rejection therefore
//! exercises proof admission rather than serialization integrity.
//!
//! Each attack lives in its own `malicious_prover_*_test.zig` beside this
//! module; this file owns the transaction entry point, the stage taxonomy and
//! the shared three-ADDI fixture they all forge against.

const std = @import("std");

const riscv_cpu = @import("stwo_riscv_cpu_integration");
const frontend = @import("stwo_riscv_frontend");
const access_clock = frontend.access_clock;
const public_data = frontend.air.public_data;
const orchestration = frontend.testing.prover_orchestration;
const trace_mod = frontend.runner.trace;

const committed = @import("committed_forgery_harness.zig");
const guest_elf = @import("guest_elf_fixture.zig");
const layout = @import("committed_row_layout.zig");

pub const Guest = committed.Guest;
pub const Row = committed.Row;
pub const ColumnValue = committed.ColumnValue;

/// Where the production pipeline refused a malicious request.
///
/// The order is the order the pipeline itself decides in, which is what makes
/// a pinned stage evidence: an attack pinned to a later stage would have been
/// caught earlier if the earlier check covered it.
pub const Stage = enum {
    /// Lookup-source ingestion, before any table is committed. Structural
    /// admission of the committed rows themselves.
    precommit_ingestion,
    /// Public-statement admission, before any transcript event.
    admission,
    /// The prover's direct-constraint check, before a proof exists.
    prover_constraints,
    /// Verification, after a proof was produced from the malicious witness.
    verification,
};

pub const Rejection = struct {
    stage: Stage,
    reason: anyerror,
};

pub const Decision = union(enum) {
    verified,
    rejected: Rejection,
};

/// One adversarial proving request.  Both fields are borrowed for the duration
/// of `attempt`; the ordinary case passes the guest's honest public data and no
/// mutation.
pub const Attempt = struct {
    statement: public_data.PublicData,
    witness: ?committed.Mutation = null,
};

/// Run an adversarial request through the production CPU prover and verifier.
///
/// Only the deliberate refusals are classified, and each is classified to the
/// stage that raised it. Every other error escapes to fail the test rather
/// than being counted as evidence that the attack was rejected: a harness that
/// mapped `anyerror` onto "rejected" would pass on a broken fixture, which is
/// the failure mode this whole file exists to rule out.
pub fn attempt(guest: *const committed.Guest, malicious: Attempt) !Decision {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    const output = orchestration.runRiscVWithEngineAndPublicDataUsingChannel(
        riscv_cpu.CpuProverEngine,
        .prove,
        guest.allocator,
        committed.PCS_CONFIG,
        &guest.run.execution_trace,
        &guest.run.state_chain_tracker,
        &guest.run.rw_memory,
        null,
        malicious.statement,
        &channel,
        malicious.witness,
        null,
    ) catch |err| switch (err) {
        // Structural admission of the committed rows, raised by
        // `air/lookups/tables/source_ingest.zig` before any table is
        // committed. Only the two placement errors are classified; the rest of
        // that module's error set describes a malformed source rather than a
        // forged row and must not be able to satisfy an attack's expectation.
        error.InactiveRealRow, error.NonZeroPadding => return .{ .rejected = .{
            .stage = .precommit_ingestion,
            .reason = err,
        } },
        error.InvalidStatement => return .{ .rejected = .{
            .stage = .admission,
            .reason = err,
        } },
        error.ConstraintsNotSatisfied => return .{ .rejected = .{
            .stage = .prover_constraints,
            .reason = err,
        } },
        else => return err,
    };

    // Verification consumes the proof on both success and failure.  The boxed
    // interaction claim remains caller-owned.
    defer output.deinitAfterProofMoved(guest.allocator);
    riscv_cpu.verifyRiscV(
        guest.allocator,
        committed.PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    ) catch |err| return .{ .rejected = .{
        .stage = .verification,
        .reason = err,
    } };
    return .verified;
}

/// Asserts the request is refused at exactly `expected_stage` with exactly
/// `expected_reason`. Both are pinned so that an unrelated failure elsewhere
/// in the pipeline cannot satisfy the test.
pub fn expectRejected(
    guest: *const committed.Guest,
    malicious: Attempt,
    expected_stage: Stage,
    expected_reason: anyerror,
) !void {
    switch (try attempt(guest, malicious)) {
        .verified => {
            std.debug.print(
                "malicious prover unexpectedly produced an accepted proof\n",
                .{},
            );
            return error.TestUnexpectedResult;
        },
        .rejected => |actual| {
            if (actual.stage != expected_stage or actual.reason != expected_reason) {
                std.debug.print(
                    "malicious-prover rejection mismatch: expected {s}/{s}, got {s}/{s}\n",
                    .{
                        @tagName(expected_stage),
                        @errorName(expected_reason),
                        @tagName(actual.stage),
                        @errorName(actual.reason),
                    },
                );
            }
            try std.testing.expectEqual(expected_stage, actual.stage);
            try std.testing.expectEqual(expected_reason, actual.reason);
        },
    }
}

// ---------------------------------------------------------------------------
// The shared fixture
// ---------------------------------------------------------------------------

// The body creates two historical versions of x3, then reads x3 into x6:
//
//   ADDI x3, x0, 7
//   ADDI x3, x3, 1      // x3 = 8
//   ADDI x6, x3, 1      // honest x6 = 9
//
// The stale-read attack rewrites only the third row to consume x3 = 7 at the
// first write's clock and coherently derive x6 = 8.
pub const BODY = [_]u32{
    0x0070_0193,
    0x0011_8193,
    0x0011_8313,
};
pub const SPEC = guest_elf.Spec{ .body = &BODY, .publish = 6 };
pub const FAMILY = trace_mod.OpcodeFamily.base_alu_imm;
pub const TARGET: committed.Target = .{ .opcode = .{ .family = FAMILY } };

/// Rows the fixture materialises for `FAMILY`: the three body ADDIs plus the
/// epilogue's two ADDIs. The prologue (`LUI`, `LUI`, `LW`) retires no row of
/// this family, so body instruction `i` is logical row `i`.
pub const FAMILY_ROWS: usize = 5;

pub const RS1_PREV_0 = layout.columnOf(FAMILY, "rs1_prev_0");
pub const RS1_CLOCK_PREV = layout.columnOf(FAMILY, "rs1_clock_prev");
pub const RS1_NEXT_0 = layout.columnOf(FAMILY, "rs1_next_0");
pub const RD_NEXT_0 = layout.columnOf(FAMILY, "rd_next_0");
pub const RESULT_0 = layout.columnOf(FAMILY, "result_0");

pub const RowValues = struct {
    values: [trace_mod.MAX_FAMILY_COLUMNS]committed.ColumnValue = undefined,
    len: usize = 0,

    pub fn set(self: *RowValues, column: usize, value: u32) void {
        self.values[self.len] = .{ .column = @intCast(column), .value = value };
        self.len += 1;
    }

    pub fn slice(self: *const RowValues) []const committed.ColumnValue {
        return self.values[0..self.len];
    }
};

/// Canonical padding over every column of a row: the committed-trace shape of
/// an instruction the prover declines to retire.
pub fn skippedRow(n_columns: usize) RowValues {
    var result = RowValues{};
    for (0..n_columns) |column| result.set(column, 0);
    return result;
}

/// The third ADDI rewritten to consume the older real x3 = 7 and the access
/// clock of its first write, with the result coherently recomputed. Every
/// row-local relation still holds; only the global access chain disagrees.
pub fn staleRead() RowValues {
    var result = RowValues{};
    result.set(RS1_PREV_0, 7);
    result.set(RS1_CLOCK_PREV, access_clock.encode(guest_elf.bodyClock(0), .second));
    result.set(RS1_NEXT_0, 7);
    result.set(RD_NEXT_0, 8);
    result.set(RESULT_0, 8);
    return result;
}

pub fn override(logical_row: u32, values: []const committed.ColumnValue) committed.Mutation {
    return .{ .main_row = .{
        .target = TARGET,
        .logical_row = logical_row,
        .values = values,
    } };
}

/// Pins that a forgery moved the memory-access bus while leaving the
/// register-state and program buses untouched, so a rejection attributable to
/// the access chain cannot be explained by a coincidental disturbance of those
/// two.
///
/// This compares exactly three of the twelve relation domains and deliberately
/// says nothing about the rest. A stale read also moves the range-check buses —
/// `entry.accessChain` requests a `range_check_20` over the clock gap and
/// `base_alu_imm` requests `range_check_8_8` over the changed result limbs — so
/// this is emphatically not a claim that the forgery moved one bus in total.
/// Whether the forgery is caught is decided by global closure over every
/// domain, which is a separate assertion; do not read this helper as covering
/// it.
pub fn expectOnlyMemoryBusMoved(
    honest: *const committed.Row,
    forged: *const committed.Row,
) !void {
    try std.testing.expect(
        try committed.busFingerprint(FAMILY, honest.slice(), .memory_access) !=
            try committed.busFingerprint(FAMILY, forged.slice(), .memory_access),
    );
    try std.testing.expectEqual(
        try committed.busFingerprint(FAMILY, honest.slice(), .registers_state),
        try committed.busFingerprint(FAMILY, forged.slice(), .registers_state),
    );
    try std.testing.expectEqual(
        try committed.busFingerprint(FAMILY, honest.slice(), .program_access),
        try committed.busFingerprint(FAMILY, forged.slice(), .program_access),
    );
}

test "malicious prover harness: the unmodified request is accepted" {
    var guest = try committed.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try std.testing.expectEqual(
        Decision.verified,
        try attempt(&guest, .{ .statement = guest.public.data }),
    );
}

// The honest leg every attack depends on. Each malicious test asserts a
// rejection, and a rejection is only evidence if the same guest is provable
// at all — otherwise every attack in this suite would pass vacuously against
// a guest that simply cannot be proven. Sail agreement rides along here so
// the run that is proven is the run the pinned model has seen. It lives in
// the shared module rather than in each attack file so the four attacks pay
// for it once.
test "malicious prover harness: the fixture guest proves, verifies and agrees with Sail" {
    var guest = try committed.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try guest.proveAndVerify("malicious-prover state-history guest");
}

test "malicious prover harness: the fixture retires the expected rows" {
    var guest = try committed.Guest.init(std.testing.allocator, SPEC);
    defer guest.deinit();
    try std.testing.expectEqual(FAMILY_ROWS, try guest.familyRowCount(FAMILY));

    // The stale-read attack is only meaningful if the honest third body row
    // really does consume the *newer* x3 = 8 at the second write's clock.
    const honest_third = try guest.honestRow(FAMILY, 2);
    try std.testing.expectEqual(@as(u32, 8), honest_third.m31At(RS1_PREV_0).toU32());
    try std.testing.expectEqual(
        access_clock.encode(guest_elf.bodyClock(1), .second),
        honest_third.m31At(RS1_CLOCK_PREV).toU32(),
    );
    try std.testing.expectEqual(@as(u32, 9), honest_third.m31At(RESULT_0).toU32());
}
