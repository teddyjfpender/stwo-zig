//! Pins for issue #152 item 3: a rejection must name its *cause* and point at
//! the diagnostic that answers it.
//!
//! Two failures each cost a full investigation:
//!
//!   - `InvalidRegisterAccessChain` raised for what was actually "an unsupported
//!     opcode reached the prover" -- a witness name for an admission defect.
//!   - `LogupSumNonZero`, raised ~1.2 s into proving, with no indication of
//!     *which* relation was unbalanced, while `riscv-trace-dump --relation-sums`
//!     and `scripts/air_satisfaction.py` sat installed beside the binary that
//!     produced it.
//!
//! ## Why this file lives here now
//!
//! It used to live in `src/tests/riscv/`, reaching back into this package with
//! `@embedFile("../../frontends/riscv/air/opcode_memory.zig")`, because no gate
//! compiled a `test` written inside this package (issue #152 item 11). That
//! reasoning was right -- a pin that does not run is not a pin -- but the
//! workaround crossed a package boundary, which
//! `scripts/check_package_workspace.py` correctly rejected.
//!
//! With the package's tests now compiled by `test-riscv-cpu-product` and by the
//! `riscv_frontend` lane, the pins that are about *this package's* sources come
//! home and the cross-package embed is gone. What stayed behind in
//! `src/tests/riscv/diagnostic_hints_test.zig` is the part that is genuinely not
//! this package's business: whether the invocations these hints publish are ones
//! `src/tools/riscv/trace`'s argument parser actually accepts. The product owns
//! both sides of that agreement; the frontend owns neither.
//!
//! ## What is pinned
//!
//! 1. **Content** -- every cause names a runnable command, no two causes share a
//!    message, and the LogUp causes name the flag that answers "which relation".
//! 2. **Attribution** -- the real pre-filter caller is driven with one trace per
//!    cause, so the mapping from raised error to remedy is asserted on errors the
//!    code actually raises.
//! 3. **Emission** -- both raise sites still call in, *and* the call still puts
//!    bytes on stderr. The second half matters: a wave-2 verifier emptied
//!    `emit`'s body and every pin in the repository stayed green, because they
//!    all checked the text of the messages and the presence of the calls. A
//!    hint nobody receives is the defect this module exists to fix.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const hints = @import("diagnostic_hints.zig");
const opcode_memory = @import("opcode_memory.zig");
const public_data = @import("public_data.zig");
const trace_mod = @import("../runner/trace.zig");

const Opcode = @import("../isa/decode.zig").Opcode;
const TraceRow = trace_mod.TraceRow;

/// The two raise sites. Embedded rather than read from disk so the wiring pins
/// have no working-directory premise and a deleted call lands at compile time.
const OPCODE_MEMORY_SOURCE = @embedFile("opcode_memory.zig");
const VERIFIER_SOURCE = @embedFile("../prover/verifier.zig");

// ---------------------------------------------------------------------------
// 1. Content
// ---------------------------------------------------------------------------

test "diagnostic hints: every cause names a diagnostic a reader can run" {
    // The property the module exists for. A hint that stops naming its tool is
    // an error name with extra words, so this fails the moment any command is
    // dropped from any message.
    for (std.enums.values(hints.Cause)) |cause| {
        const text = hints.hint(cause);
        try std.testing.expect(text.len != 0);

        var names_a_command = std.mem.indexOf(u8, text, hints.CHECK_AIR) != null;
        for (hints.INVOCATIONS) |invocation| {
            if (std.mem.indexOf(u8, text, invocation) != null) names_a_command = true;
        }
        if (!names_a_command) {
            std.debug.print(
                "hint for {s} names no runnable diagnostic:\n  {s}\n",
                .{ @tagName(cause), text },
            );
            return error.HintNamesNoDiagnostic;
        }
    }
}

test "diagnostic hints: the LogUp causes name the per-relation sums dump" {
    // `--relation-sums` is the flag that answers "which relation", which is the
    // exact question `LogupSumNonZero` cannot answer on its own: a component's
    // claimed sum is one field element covering every relation it touches, so
    // the residual has no decomposition the verifier can compute. Naming the
    // dumper without naming that mode would not close the gap.
    for ([_]hints.Cause{ .logup_no_public_io, .logup_unattributed }) |cause| {
        const text = hints.hint(cause);
        try std.testing.expect(std.mem.indexOf(u8, text, hints.DUMP_SUMS) != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "--relation-sums") != null);
    }
}

test "diagnostic hints: each cause gets its own message" {
    // Causes collapsing onto one text would reintroduce the defect under a new
    // name: a reader told the same thing for an admission failure and a witness
    // failure learns nothing from being told.
    const causes = std.enums.values(hints.Cause);
    for (causes, 0..) |left, i| {
        for (causes[i + 1 ..]) |right| {
            if (!std.mem.eql(u8, hints.hint(left), hints.hint(right))) continue;
            std.debug.print(
                "causes {s} and {s} share one message\n",
                .{ @tagName(left), @tagName(right) },
            );
            return error.CausesShareOneMessage;
        }
    }
}

test "diagnostic hints: the host and cross-target dumper names stay distinct" {
    // Issue #152 item 6a: the host and cross-target dumpers were once both
    // installed as `riscv-trace-dump`, so a static build replaced the native
    // binary and the next native run died with `Exec format error`. A message
    // naming the wrong one sends its reader to a binary that cannot execute.
    // That these are the names the build actually installs is checked by
    // `src/tests/riscv/diagnostic_hints_test.zig`, which can read the build file.
    try std.testing.expect(!std.mem.eql(u8, hints.TRACE_DUMP, hints.TRACE_DUMP_STATIC));
    try std.testing.expect(std.mem.startsWith(u8, hints.TRACE_DUMP_STATIC, hints.TRACE_DUMP));
    // Only the host binary is runnable where a hint is read, so no hint may hand
    // a reader the musl build.
    for (hints.INVOCATIONS) |invocation| {
        try std.testing.expect(
            std.mem.indexOf(u8, invocation, hints.TRACE_DUMP_STATIC) == null,
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Cause attribution
// ---------------------------------------------------------------------------

test "diagnostic hints: the two register-boundary causes stay distinct" {
    // Behavioural, not just tabular: the real pre-filter caller is driven with
    // one trace per cause, and each must classify to its own remedy.
    //
    // An ECALL row is an admission failure in the caller. A representable row
    // whose access chain does not close is a witness failure. Reporting the
    // first as the second is what cost a full investigation, so the mapping from
    // raised error to remedy is asserted on errors the code actually raises
    // rather than on hand-written error values.
    const with_ecall = [_]TraceRow{ addiRow(1, 0x10000, 1, 42), ecallRow(2, 0x10004) };
    const broken_chain = [_]TraceRow{danglingAddiRow(1, 0x10000)};

    try std.testing.expectError(
        error.UnsupportedForProof,
        opcode_memory.deriveRegisterBoundary(&with_ecall),
    );
    try std.testing.expectError(
        error.InvalidRegisterAccessChain,
        opcode_memory.deriveRegisterBoundary(&broken_chain),
    );

    try std.testing.expectEqual(
        hints.Cause.unsupported_opcode,
        hints.classifyRegisterBoundary(@as(anyerror, error.UnsupportedForProof)),
    );
    try std.testing.expectEqual(
        hints.Cause.register_access_chain,
        hints.classifyRegisterBoundary(@as(anyerror, error.InvalidRegisterAccessChain)),
    );

    // And the admission message must not describe a witness defect.
    const text = hints.hint(.unsupported_opcode);
    try std.testing.expect(std.mem.indexOf(u8, text, "ECALL") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "access chain") == null);
}

test "diagnostic hints: a statement declaring no public I/O gets its own message" {
    // The one LogUp shape a verifier can recognise unaided. It holds only the
    // statement, the proof and the interaction claim, so it cannot attribute a
    // residual to a relation -- but it can see that the statement compensates no
    // public-I/O tuples at all, which no witness can balance if the guest
    // performed I/O.
    try std.testing.expectEqual(hints.Cause.logup_no_public_io, hints.classifyLogup(false));
    try std.testing.expectEqual(hints.Cause.logup_unattributed, hints.classifyLogup(true));
    try std.testing.expect(
        std.mem.indexOf(u8, hints.hint(.logup_no_public_io), "declares no public I/O") != null,
    );

    // The predicate the verifier reads, on the data it reads it from.
    const input = [_]u32{7};
    const output = [_]public_data.OutputWord{.{ .addr = 0x2000, .value = 1, .clock = 3 }};
    try std.testing.expect(!statementWith(&.{}, &.{}).declaresPublicIo());
    try std.testing.expect(statementWith(&input, &.{}).declaresPublicIo());
    try std.testing.expect(statementWith(&.{}, &output).declaresPublicIo());
    try std.testing.expect(statementWith(&input, &output).declaresPublicIo());
}

// ---------------------------------------------------------------------------
// 3. Emission
// ---------------------------------------------------------------------------

test "diagnostic hints: both raise sites still report before propagating" {
    // The classifier and its messages can be perfect and still tell nobody
    // anything if the raise site stops calling them.
    try expectCalls(
        OPCODE_MEMORY_SOURCE,
        "air/opcode_memory.zig",
        "diagnostic_hints.reportRegisterBoundary(",
    );
    try expectCalls(
        VERIFIER_SOURCE,
        "prover/verifier.zig",
        "diagnostic_hints.reportLogupImbalance(",
    );

    // The LogUp report must hang off the cancellation check itself. Emitting it
    // anywhere else would either fire on success or miss the failure.
    const check = std.mem.indexOf(u8, VERIFIER_SOURCE, "verifyGlobalCancellation(") orelse
        return error.CancellationCheckMissing;
    const report = std.mem.indexOf(u8, VERIFIER_SOURCE, "reportLogupImbalance(").?;
    try std.testing.expect(check < report);
    try std.testing.expect(std.mem.indexOf(u8, VERIFIER_SOURCE[check..report], "catch") != null);

    // Same for the register boundary: the report sits on the error path of the
    // derivation, not on its success path.
    const derive = std.mem.indexOf(
        u8,
        OPCODE_MEMORY_SOURCE,
        "deriveRegisterBoundaryUnreported(rows) catch",
    ) orelse return error.RegisterBoundaryErrorPathMissing;
    const boundary_report =
        std.mem.indexOf(u8, OPCODE_MEMORY_SOURCE, "reportRegisterBoundary(").?;
    try std.testing.expect(derive < boundary_report);
}

test "diagnostic hints: the register-boundary report reaches stderr" {
    // Observed, not inferred. Every other pin here reads source text or message
    // constants, and all of them stayed green when `emit`'s body was emptied --
    // the module kept its perfect messages and delivered none of them. This is
    // the pin that fails for that mutation.
    const allocator = std.testing.allocator;
    const written = try captureStderr(allocator, struct {
        fn call() void {
            hints.reportRegisterBoundary(@as(anyerror, error.UnsupportedForProof));
        }
    }.call);
    defer allocator.free(written);

    try std.testing.expect(written.len != 0);
    // The error name, so a reader can match it against what the caller saw.
    try std.testing.expect(std.mem.indexOf(u8, written, "UnsupportedForProof") != null);
    // The remedy for *this* cause, not merely some remedy.
    try std.testing.expect(
        std.mem.indexOf(u8, written, hints.hint(.unsupported_opcode)) != null,
    );
    // One line per failure: the adversarial suites drive this path dozens of
    // times per process and a multi-line report would bury them.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, written, "\n"));
}

test "diagnostic hints: the LogUp report reaches stderr with its residual" {
    const allocator = std.testing.allocator;
    const written = try captureStderr(allocator, struct {
        fn call() void {
            hints.reportLogupImbalance(QM31.fromU32Unchecked(7, 0, 0, 0), false);
        }
    }.call);
    defer allocator.free(written);

    try std.testing.expect(written.len != 0);
    // The residual distinguishes a wrong-by-one-tuple failure from a
    // structurally absent bus, which is the first thing a reader needs.
    try std.testing.expect(std.mem.indexOf(u8, written, "7") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, written, hints.hint(.logup_no_public_io)) != null,
    );
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, written, "\n"));
}

/// Run `emitter` with this process's stderr redirected into a temporary file and
/// return everything it wrote.
///
/// `std.debug.print` writes to file descriptor 2 and flushes before returning,
/// so redirecting the descriptor is enough and no seam has to be cut into the
/// module under test. The alternative -- a mutable sink in production library
/// code so a test can substitute a buffer -- was rejected when these pins were
/// textual, and it is still the worse trade.
fn captureStderr(
    allocator: std.mem.Allocator,
    comptime emitter: fn () void,
) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var file = try tmp.dir.createFile("stderr.txt", .{});
        defer file.close();
        const saved = try std.posix.dup(std.posix.STDERR_FILENO);
        defer std.posix.close(saved);
        try std.posix.dup2(file.handle, std.posix.STDERR_FILENO);
        // Restored before `saved` is closed: `defer` unwinds last-declared-first.
        defer std.posix.dup2(saved, std.posix.STDERR_FILENO) catch {};
        emitter();
    }
    return tmp.dir.readFileAlloc(allocator, "stderr.txt", 1 << 16);
}

fn expectCalls(source: []const u8, owner: []const u8, call: []const u8) !void {
    if (std.mem.indexOf(u8, source, call) != null) return;
    std.debug.print("{s} no longer calls {s}\n", .{ owner, call });
    return error.RaiseSiteStoppedReporting;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn statementWith(
    input_words: []const u32,
    output_words: []const public_data.OutputWord,
) public_data.PublicData {
    return .{
        .initial_pc = 0x10000,
        .final_pc = 0x10004,
        .clock = 1,
        .initial_regs = .{0} ** 32,
        .final_regs = .{0} ** 32,
        .reg_last_clock = .{0} ** 32,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .io_entries = .{
            .input_start = 0x1000,
            .input_len = @intCast(input_words.len * 4),
            .input_words = input_words,
            .output_len = if (output_words.len == 0) 0 else 4,
            .output_len_addr = 0x1ffc,
            .output_data_addr = 0x2000,
            .output_words = output_words,
        },
    };
}

/// `addi xrd, x0, imm`: one x0 source read and one destination write, both at
/// their first observation, so the access chain closes on its own.
fn addiRow(clk: u32, pc: u32, rd: u5, value: u32) TraceRow {
    return .{
        .clk = clk,
        .pc = pc,
        .opcode = .ADDI,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = @intCast(value),
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = value,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = 0x02A00093,
    };
}

/// The same shape, but claiming a prior write to `rs1` that the trace never
/// shows. `observe` requires a first observation to carry `previous_clock == 0`,
/// so this is a representable row whose chain does not close -- the witness
/// failure, with no unsupported opcode anywhere in it.
fn danglingAddiRow(clk: u32, pc: u32) TraceRow {
    var row = addiRow(clk, pc, 2, 7);
    row.rs1 = 5;
    row.rs1_prev_clk = 9;
    return row;
}

/// The row the runner appends for an ECALL: architectural register fields are
/// populated, which is what let the mis-derived family observe rs1/rs2 that no
/// proof row should have read.
fn ecallRow(clk: u32, pc: u32) TraceRow {
    return .{
        .clk = clk,
        .pc = pc,
        .opcode = Opcode.ECALL,
        .rd = 0,
        .rs1 = 7,
        .rs2 = 9,
        .imm = 0,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc + 4,
        .inst_word = 0x00000073,
    };
}
