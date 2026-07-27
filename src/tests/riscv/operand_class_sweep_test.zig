//! Every Sail-derived operand-class case, run honestly end to end through
//! the production runner and decided by the row-local AIR oracle.
//!
//! This is the seam between soundness legs 1 and 2, tested on operands
//! Sail chose rather than operands we thought of. For each corpus case:
//!
//!  1. the guest fixture wraps the case body verbatim and the runner
//!     executes it -- the same body words the pinned Sail model retired at
//!     generation time;
//!  2. the retirement path and every pinned retirement field (destination
//!     write, next-pc step, memory effect, and the reconstructed source
//!     operands) must equal Sail's recorded answers -- leg 1, on class
//!     operands, in-process;
//!  3. the under-test instruction's committed row must be admissible under
//!     the row oracle (direct constraints AND preprocessed lookup
//!     membership) -- the honest half of leg 2, on the same operands.
//!
//! A failure in 2 is a runner-vs-Sail divergence; a failure in 3 is an
//! honest witness the AIR rejects, i.e. a completeness bug in a constraint
//! or lookup at exactly the operand class the case names. Both name the
//! case, so "what broke" arrives as `divu/div_by_zero`, not a row number.
//! `KNOWN_COMPLETENESS_REJECTIONS` records the finding this sweep made on
//! its first run, with its cause; the sweep asserts those cases still
//! fail, so an AIR fix must revisit the note rather than leave it stale.
//!
//! What this file does NOT show: uniqueness (a forged row could still be
//! admissible; the mutation suites and the SMT board own that), and only
//! the known-rejection demonstration below proves anything end to end --
//! the corpus rows enter the witness audits through `rigidity_corpus`,
//! which executes these same guests.
//!
//! Runtime: about a quarter second for the 292-case sweep (guest
//! executions of at most ~25 retirements plus one family materialization
//! per case; measured on an M-series CPU, printed per run, bounded by
//! corpus size) plus about two seconds for the end-to-end demonstration,
//! which stops inside one proof attempt.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const guest_elf = @import("guest_elf_fixture.zig");
const operand_classes = @import("operand_classes.zig");
const row_admissibility = @import("row_admissibility.zig");
const isa_decode = @import("../../frontends/riscv/isa/decode.zig");
const opcode_manifest = @import("../../frontends/riscv/opcode_manifest.zig");
const public_values = @import("../../frontends/riscv/diagnostics/public_values.zig");
const runner = @import("../../frontends/riscv/runner/mod.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");
const riscv_cpu = @import("../../integrations/riscv_cpu/mod.zig");

const Case = operand_classes.Case;

test {
    // The corpus's structural self-checks travel with its consumer.
    _ = operand_classes;
}

/// The completeness findings this sweep made on its first run live as
/// corpus metadata (`operand_classes.KNOWN_COMPLETENESS_REJECTIONS`, with
/// the full cause); this alias keeps the assertions below readable.
const isKnownRejection = operand_classes.isKnownCompletenessRejection;

/// Whether the encoding class of `op` carries a live rs1/rs2 operand, i.e.
/// whether the corpus recorded a source value worth comparing. Shift
/// immediates carry their amount in the rs2 field, so only rs1 is data.
fn readsSources(op: isa_decode.Opcode) struct { rs1: bool, rs2: bool } {
    const entry = opcode_manifest.entry(isa_decode.proofOpcode(op) catch unreachable);
    return switch (entry.encoding_class) {
        .r_type, .s_type, .b_type => .{ .rs1 = true, .rs2 = true },
        .i_type => .{ .rs1 = true, .rs2 = false },
        .u_type, .j_type, .misc_mem => .{ .rs1 = false, .rs2 = false },
    };
}

/// Whether a body word architecturally writes rd. S/B encodings reuse the
/// rd bit range for immediate fragments, and the in-process `TraceRow.rd`
/// keeps those raw bits (only the canonical trace dump normalizes them to
/// RVFI's zero), so rd and rd_value are only comparable where rd is real.
fn writesRd(word: u32) !bool {
    const decoded = try isa_decode.DecodedInst.decode(word);
    const entry = opcode_manifest.entry(try isa_decode.proofOpcode(decoded.opcode));
    return switch (entry.encoding_class) {
        .r_type, .i_type, .u_type, .j_type => true,
        .s_type, .b_type, .misc_mem => false,
    };
}

/// The retirements of the case body, in execution order, as (body index,
/// trace row) pairs. Prologue and epilogue rows fall outside the body's pc
/// window and are not the case's to check.
const BodyRows = struct {
    indices: [64]u8 = undefined,
    rows: [64]trace_mod.TraceRow = undefined,
    len: usize = 0,

    fn collect(trace: *const trace_mod.Trace, body_len: usize) !BodyRows {
        const first = guest_elf.bodyPc(0);
        const end = guest_elf.bodyPc(body_len);
        var out = BodyRows{};
        for (trace.rows.items) |row| {
            if (row.pc < first or row.pc >= end) continue;
            if (out.len == out.rows.len) return error.BodyTooLong;
            out.indices[out.len] = @intCast((row.pc - first) / 4);
            out.rows[out.len] = row;
            out.len += 1;
        }
        return out;
    }

    fn rowAt(self: *const BodyRows, index: usize) !trace_mod.TraceRow {
        for (self.indices[0..self.len], self.rows[0..self.len]) |i, row| {
            if (i == index) return row;
        }
        return error.CheckedRowNeverRetired;
    }
};

fn expectRetirementPath(case: *const Case, body_rows: *const BodyRows) !void {
    // The retired index sequence pins the control-flow decisions: a branch
    // that went the other way, or a skipped instruction that retired,
    // changes this sequence before any value comparison could notice.
    try std.testing.expectEqual(case.retired.len, body_rows.len);
    for (case.retired, body_rows.indices[0..body_rows.len]) |expected, actual| {
        try std.testing.expectEqual(expected, actual);
    }
}

fn expectCheckedFields(case: *const Case, body_rows: *const BodyRows) !void {
    for (case.checks) |check| {
        const row = try body_rows.rowAt(check.index);
        if (try writesRd(case.body[check.index])) {
            try std.testing.expectEqual(check.rd, row.rd);
            try std.testing.expectEqual(check.expectedRdValue(row.pc), row.rd_val);
        }
        try std.testing.expectEqual(check.expectedNextPc(row.pc), row.next_pc);
        if (check.touchesMemory()) {
            try std.testing.expectEqual(check.mem_addr, row.mem_addr);
            try std.testing.expectEqual(check.mem_rmask != 0, row.is_load);
            try std.testing.expectEqual(check.mem_wmask != 0, row.is_store);
        }
    }
    // The under-test retirement additionally pins decode and the source
    // operand values the runner saw against the Sail-derived ones the
    // corpus recorded. pc-derived operands carry no portable value.
    const row = try body_rows.rowAt(case.under_test);
    try std.testing.expectEqual(case.op, row.opcode);
    const sources = readsSources(case.op);
    if (sources.rs1 and !case.rs1_pc_derived)
        try std.testing.expectEqual(case.rs1_val, row.rs1_val);
    if (sources.rs2 and !case.rs2_pc_derived)
        try std.testing.expectEqual(case.rs2_val, row.rs2_val);
}

/// Family-relative index of the under-test row: how many earlier
/// retirements of the whole run (prologue included) share its family.
/// `Trace.columnsForFamily` fills committed rows in execution order, so
/// this is its position there.
fn familyLogicalRow(
    trace: *const trace_mod.Trace,
    family: trace_mod.OpcodeFamily,
    pc: u32,
) !usize {
    var logical: usize = 0;
    for (trace.rows.items) |row| {
        const row_family = trace_mod.proofOpcodeFamily(row.opcode) catch continue;
        if (row.pc == pc and row_family == family) return logical;
        if (row_family == family) logical += 1;
    }
    return error.UnderTestRowNotInTrace;
}

/// Row-oracle verdict on the under-test committed row.
fn underTestRowVerdict(
    allocator: std.mem.Allocator,
    case: *const Case,
    run: *const runner.RunResult,
) !row_admissibility.Verdict {
    const family = trace_mod.opcodeFamily(case.op);
    const trace = &run.execution_trace;
    const pc = guest_elf.bodyPc(case.under_test);
    const logical = try familyLogicalRow(trace, family, pc);

    var counts = try trace.groupByOpcodeFamily(allocator);
    const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, counts.get(family)));
    var columns = try trace.columnsForFamily(allocator, family, log_size);
    defer columns.deinit(allocator);
    try std.testing.expect(logical < columns.n_real_rows);

    var cells: [trace_mod.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (columns.columns[0..columns.n_columns], 0..) |column, index| {
        cells[index] = QM31.fromBase(column[logical]);
    }
    return row_admissibility.verdict(family, cells[0..columns.n_columns]);
}

fn runCase(allocator: std.mem.Allocator, case: *const Case) !void {
    const spec = guest_elf.Spec{ .body = case.body };
    const elf = try guest_elf.build(allocator, spec);
    defer allocator.free(elf);
    var run = try runner.runWithInput(allocator, elf, &guest_elf.INPUT, guest_elf.maxSteps(spec));
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.halt_flag, run.completion_reason);

    const body_rows = try BodyRows.collect(&run.execution_trace, case.body.len);
    try expectRetirementPath(case, &body_rows);
    try expectCheckedFields(case, &body_rows);

    // A known completeness rejection must stay rejected: silently becoming
    // admissible would leave the note above describing a fixed bug as live.
    const verdict = try underTestRowVerdict(allocator, case, &run);
    if (isKnownRejection(case.name)) {
        switch (verdict) {
            .accepted => {
                std.debug.print(
                    "{s}: known completeness rejection is now admissible; " ++
                        "remove it from KNOWN_COMPLETENESS_REJECTIONS\n",
                    .{case.name},
                );
                return error.KnownRejectionNowAdmissible;
            },
            else => return,
        }
    }
    switch (verdict) {
        .accepted => {},
        .direct_constraints => {
            std.debug.print(
                "{s}: honest {s} row fails a direct constraint\n",
                .{ case.name, @tagName(trace_mod.opcodeFamily(case.op)) },
            );
            return error.HonestClassRowRejected;
        },
        .table => |rejection| {
            std.debug.print(
                "{s}: honest {s} row rejected by {s} request {d}\n",
                .{
                    case.name,
                    @tagName(trace_mod.opcodeFamily(case.op)),
                    @tagName(rejection.domain),
                    rejection.index,
                },
            );
            return error.HonestClassRowRejected;
        },
    }
}

// Runtime: about four seconds for all 292 cases; the realised figure and
// per-family case counts are printed so a slowdown or a shrunken corpus is
// visible in the log rather than silent.
test "operand class sweep: runner and AIR agree with Sail on every enumerated class case" {
    const allocator = std.testing.allocator;
    var timer = try std.time.Timer.start();
    var failures: usize = 0;
    var family_counts = [_]usize{0} ** trace_mod.N_FAMILIES;
    for (operand_classes.all) |case| {
        runCase(allocator, &case) catch |err| {
            std.debug.print("FAILED {s}: {s}\n", .{ case.name, @errorName(err) });
            failures += 1;
        };
        family_counts[@intFromEnum(trace_mod.opcodeFamily(case.op))] += 1;
    }
    const elapsed_ms = timer.read() / std.time.ns_per_ms;
    std.debug.print(
        "\n  operand class sweep: {d} cases in {d} ms; per family:\n",
        .{ operand_classes.all.len, elapsed_ms },
    );
    for (family_counts, 0..) |count, index| {
        if (count == 0) continue;
        std.debug.print("    {s: <14} {d: >3}\n", .{
            @tagName(@as(trace_mod.OpcodeFamily, @enumFromInt(index))), count,
        });
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}

// Runtime: about two seconds -- one refused proof attempt of a
// nine-instruction guest; the prover stops while ingesting lookup sources.
test "operand class sweep: the DIVU big-quotient completeness rejection is real end to end" {
    // The row-local verdict above says the honest row asks range_check_m31
    // for a tuple that does not exist. This shows production agrees, one
    // stage earlier than a forged row would fail: the prover's lookup
    // source ingest cannot index the request `{0, q[3]}` with q[3] = 0x8a,
    // so the honest guest cannot be PROVEN at all -- `ValueOutOfRange`
    // from the range_check_m31 pair schema, no proof object ever exists.
    // When the AIR is fixed this test must become a proveAndVerify
    // expectation and the KNOWN_COMPLETENESS_REJECTIONS entries must go.
    const case = comptime operand_classes.named("divu/div_divisor_one");
    const allocator = std.testing.allocator;
    const spec = guest_elf.Spec{ .body = case.body };
    const elf = try guest_elf.build(allocator, spec);
    defer allocator.free(elf);
    var run = try runner.runWithInput(allocator, elf, &guest_elf.INPUT, guest_elf.maxSteps(spec));
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.halt_flag, run.completion_reason);
    // Sail's answer for x / 1, retired honestly by the runner.
    try std.testing.expectEqual(case.underTestCheck().rd_value, run.final_regs[10]);

    var public = try public_values.derive(allocator, &run);
    defer public.deinit(allocator);
    const config = pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
        },
    };
    try std.testing.expectError(error.ValueOutOfRange, riscv_cpu.proveRiscVWithPublicData(
        allocator,
        config,
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
        null,
        public.data,
    ));
}
