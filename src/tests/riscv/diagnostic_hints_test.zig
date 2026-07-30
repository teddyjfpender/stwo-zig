//! Regression pins for issue #152 item 3: errors must name their *cause* and
//! point at the diagnostic that answers them.
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
//! `air/diagnostic_hints.zig` closes the second gap by emitting a remediation
//! line at each raise site. This file is what keeps that closed, and it lives
//! here rather than beside the module for a load-bearing reason:
//! **`src/frontends/riscv/**` is a separate Zig module (`stwo_riscv_frontend`),
//! so its in-file tests are compiled by no gate in this repository.** They are
//! reachable only through `src/frontends/riscv/build.zig`'s own `test` step,
//! which no product step, release gate or workflow depends on -- verified by
//! `-Driscv-test-filter`, which reports "selects no test" for every test name
//! defined under `src/frontends/riscv/`. A pin that does not run is not a pin,
//! so every property this file cares about is asserted from the root test
//! module, which `test-riscv-cpu-product` compiles and runs.
//!
//! Three kinds of pin, in increasing order of strength:
//!
//! 1. **Content** -- every cause names a runnable command, and the LogUp causes
//!    name the flag that answers "which relation".
//! 2. **Grammar** -- every invocation a hint publishes is checked against the
//!    dumper's own argument parser, re-derived from its source. This is not
//!    theoretical: the first draft of the hints advertised
//!    `--elf <elf> ... --relation-sums <out.json>`, and the dumper rejects that
//!    with `error.ConflictingOptions`, because `--relation-sums` is itself a
//!    mode whose value is the ELF path. A hint that cannot be pasted into a
//!    shell is worse than silence, since it reads as authoritative.
//! 3. **Wiring** -- the two raise sites still emit before they propagate.
//!    Textual, because observing the emission would mean putting a mutable
//!    redirect into production library code; a source pin costs nothing and
//!    fails when the call is deleted, which is the regression that matters.
//!
//! Also pinned: the dumper's *installed* names, against the build file that
//! installs them. Naming the wrong one sends a reader to a binary that cannot
//! run -- the concrete cost of issue #152 item 6a, where a cross build replaced
//! the host dumper and the next native run died with `Exec format error`.

const std = @import("std");

const frontend = @import("stwo_riscv_frontend");
const hints = frontend.air.diagnostic_hints;
const opcode_memory = frontend.air.opcode_memory;
const public_data = frontend.air.public_data;
const trace_mod = frontend.runner.trace;

const Opcode = frontend.isa.decode.Opcode;
const TraceRow = trace_mod.TraceRow;

/// The trace dumper's own source. Embedded rather than read from disk so the
/// grammar check has no working-directory premise, and so a flag rename lands
/// here at compile time.
const DUMPER_SOURCE = @embedFile("../../tools/riscv/trace/main.zig");

/// The two raise sites, for the wiring pins below.
const OPCODE_MEMORY_SOURCE = @embedFile("../../frontends/riscv/air/opcode_memory.zig");
const VERIFIER_SOURCE = @embedFile("../../frontends/riscv/prover/verifier.zig");

/// The build file that installs the dumper, read at run time because it sits
/// outside this module's directory. Tests run from the repository root.
const BUILD_FILE = "build_support/products/riscv_cpu.zig";

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
    // Four causes collapsing onto one text would reintroduce exactly the defect
    // under a new name: a reader told the same thing for an admission failure
    // and a witness failure learns nothing from being told.
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

// ---------------------------------------------------------------------------
// 2. Grammar
// ---------------------------------------------------------------------------

/// One `--flag` the dumper parses, and whether it is a *mode*.
const Flag = struct {
    name: []const u8,
    /// Modes are mutually exclusive: `main.zig` counts them and rejects any
    /// invocation naming more or fewer than one.
    mode: bool,
    /// The `main.zig` local the mode is captured in, used to read the
    /// `--input` compatibility guard.
    ident: []const u8,
};

/// The dumper's flag table, re-derived from its source.
///
/// Deriving rather than restating is the whole point: a table copied here by
/// hand would agree with the hints and disagree with the tool, which is the
/// failure mode being pinned.
fn parseFlags(allocator: std.mem.Allocator) ![]Flag {
    var flags: std.ArrayList(Flag) = .{};
    errdefer flags.deinit(allocator);

    // Every accepted flag is compared as `std.mem.eql(u8, args[i], "--name")`.
    const needle = "args[i], \"";
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, DUMPER_SOURCE, cursor, needle)) |hit| {
        const start = hit + needle.len;
        const end = std.mem.indexOfScalarPos(u8, DUMPER_SOURCE, start, '"') orelse
            return error.UnterminatedFlagLiteral;
        try flags.append(allocator, .{
            .name = DUMPER_SOURCE[start..end],
            .mode = false,
            .ident = "",
        });
        cursor = end;
    }
    if (flags.items.len == 0) return error.NoFlagsParsed;

    // The mode set is the argument list of `countPresent`.
    const modes_open = "countPresent(.{";
    const open = std.mem.indexOf(u8, DUMPER_SOURCE, modes_open) orelse
        return error.NoModeListFound;
    const list_start = open + modes_open.len;
    const list_end = std.mem.indexOfPos(u8, DUMPER_SOURCE, list_start, "});") orelse
        return error.UnterminatedModeList;

    var idents = std.mem.tokenizeAny(u8, DUMPER_SOURCE[list_start..list_end], ", \n\r\t");
    var mode_count: usize = 0;
    while (idents.next()) |ident| {
        mode_count += 1;
        const flag = try flagForIdent(ident);
        for (flags.items) |*entry| {
            if (!std.mem.eql(u8, entry.name, flag)) continue;
            entry.mode = true;
            entry.ident = ident;
            break;
        } else {
            std.debug.print(
                "mode local '{s}' maps to '{s}', which the dumper does not parse\n",
                .{ ident, flag },
            );
            return error.ModeFlagNotParsed;
        }
    }
    // A new mode that this mapping cannot resolve fails above; a mode list that
    // shrank to nothing fails here.
    if (mode_count == 0) return error.NoModesParsed;
    return flags.toOwnedSlice(allocator);
}

/// `relation_sums` -> `--relation-sums`; `elf_path` -> `--elf`.
fn flagForIdent(ident: []const u8) ![]const u8 {
    const table = [_]struct { []const u8, []const u8 }{
        .{ "elf_path", "--elf" },
        .{ "decode_file", "--decode-file" },
        .{ "program_tuples", "--program-tuples" },
        .{ "poseidon2_file", "--poseidon2-file" },
        .{ "transcript_prefix", "--transcript-prefix" },
        .{ "witness_rows", "--witness-rows" },
        .{ "ordered_accesses", "--ordered-accesses" },
        .{ "relation_tuples", "--relation-tuples" },
        .{ "relation_sums", "--relation-sums" },
        .{ "public_values", "--public-values" },
    };
    for (table) |pair| {
        if (std.mem.eql(u8, pair[0], ident)) return pair[1];
    }
    std.debug.print("no flag known for dumper mode local '{s}'\n", .{ident});
    return error.UnknownModeLocal;
}

test "diagnostic hints: every invocation is one the dumper accepts" {
    // The pin that caught a wrong invocation already. `--relation-sums` and
    // `--relation-tuples` are modes taking the ELF path, not output paths, and
    // `main.zig` refuses `mode_count != 1`.
    const allocator = std.testing.allocator;
    const flags = try parseFlags(allocator);
    defer allocator.free(flags);

    // The guard that decides which modes may be combined with `--input`.
    const guard_open = "if (input_path != null";
    const guard_start = std.mem.indexOf(u8, DUMPER_SOURCE, guard_open) orelse
        return error.NoInputGuardFound;
    const guard_end = std.mem.indexOfPos(
        u8,
        DUMPER_SOURCE,
        guard_start,
        "return error.ConflictingOptions;",
    ) orelse return error.UnterminatedInputGuard;
    const input_guard = DUMPER_SOURCE[guard_start..guard_end];

    for (hints.INVOCATIONS) |invocation| {
        var tokens = std.mem.tokenizeScalar(u8, invocation, ' ');
        const program = tokens.next() orelse return error.EmptyInvocation;
        try std.testing.expectEqualStrings(hints.TRACE_DUMP, program);

        var modes: usize = 0;
        var mode_ident: []const u8 = "";
        var names_input = false;
        while (tokens.next()) |token| {
            if (!std.mem.startsWith(u8, token, "--")) continue;
            const flag = for (flags) |entry| {
                if (std.mem.eql(u8, entry.name, token)) break entry;
            } else {
                std.debug.print(
                    "invocation `{s}` names {s}, which the dumper does not parse\n",
                    .{ invocation, token },
                );
                return error.InvocationNamesUnknownFlag;
            };
            if (flag.mode) {
                modes += 1;
                mode_ident = flag.ident;
            }
            if (std.mem.eql(u8, token, "--input")) names_input = true;
        }

        if (modes != 1) {
            std.debug.print(
                "invocation `{s}` names {d} mode flags; the dumper requires exactly 1\n",
                .{ invocation, modes },
            );
            return error.InvocationModeCountWrong;
        }
        if (names_input and std.mem.indexOf(u8, input_guard, mode_ident) == null) {
            std.debug.print(
                "invocation `{s}` passes --input to a mode that rejects it\n",
                .{invocation},
            );
            return error.InvocationInputRejected;
        }
    }
}

test "diagnostic hints: every flag mentioned in prose is a flag the dumper parses" {
    // Invocations are checked above; this covers a flag named on its own inside
    // a sentence, which is how advice usually rots.
    const allocator = std.testing.allocator;
    const flags = try parseFlags(allocator);
    defer allocator.free(flags);

    for (std.enums.values(hints.Cause)) |cause| {
        var tokens = std.mem.tokenizeAny(u8, hints.hint(cause), " `,.;");
        while (tokens.next()) |token| {
            if (!std.mem.startsWith(u8, token, "--")) continue;
            for (flags) |entry| {
                if (std.mem.eql(u8, entry.name, token)) break;
            } else {
                std.debug.print(
                    "hint for {s} names {s}, which the dumper does not parse\n",
                    .{ @tagName(cause), token },
                );
                return error.HintNamesUnknownFlag;
            }
        }
    }
}

test "diagnostic hints: the named diagnostics exist on disk" {
    // A hint pointing at a deleted script is the same defect as no hint. Fails
    // closed rather than skipping: a harness that cannot see the repository
    // root should say so, not quietly stop checking.
    std.fs.cwd().access(hints.AIR_SATISFACTION, .{}) catch |err| {
        std.debug.print(
            "hints name '{s}', which is not readable from the test working directory: {s}\n",
            .{ hints.AIR_SATISFACTION, @errorName(err) },
        );
        return error.NamedDiagnosticMissing;
    };
}

test "diagnostic hints: the dumper names match the build that installs them" {
    // Issue #152 item 6a: the host and cross-target dumpers were once both
    // installed as `riscv-trace-dump`, so a static build replaced the native
    // binary and the next native run died with `Exec format error`. A message
    // naming the wrong one sends its reader to a binary that cannot execute,
    // so these constants must track the build file rather than a memory of it.
    const allocator = std.testing.allocator;
    const source = std.fs.cwd().readFileAlloc(allocator, BUILD_FILE, 1 << 20) catch |err| {
        std.debug.print(
            "cannot read '{s}' from the test working directory: {s}\n",
            .{ BUILD_FILE, @errorName(err) },
        );
        return error.BuildFileUnreadable;
    };
    defer allocator.free(source);

    for ([_][]const u8{ hints.TRACE_DUMP, hints.TRACE_DUMP_STATIC }) |name| {
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{name});
        defer allocator.free(quoted);
        if (std.mem.indexOf(u8, source, quoted) != null) continue;
        std.debug.print(
            "the hints name an artifact '{s}' that {s} does not install\n",
            .{ name, BUILD_FILE },
        );
        return error.DumperNameNotInstalled;
    }
    // Distinct, and the cross-target one target-qualified, so neither message
    // can be read as naming the other.
    try std.testing.expect(!std.mem.eql(u8, hints.TRACE_DUMP, hints.TRACE_DUMP_STATIC));
    try std.testing.expect(std.mem.startsWith(u8, hints.TRACE_DUMP_STATIC, hints.TRACE_DUMP));
    // Only the host binary is runnable where a hint is read, so no hint may
    // hand a reader the musl build.
    for (hints.INVOCATIONS) |invocation| {
        try std.testing.expect(
            std.mem.indexOf(u8, invocation, hints.TRACE_DUMP_STATIC) == null,
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Cause attribution
// ---------------------------------------------------------------------------

test "diagnostic hints: the two register-boundary causes stay distinct" {
    // Behavioural, not just tabular: the real pre-filter caller is driven with
    // one trace per cause, and each must classify to its own remedy.
    //
    // An ECALL row is an admission failure in the caller. A representable row
    // whose access chain does not close is a witness failure. Reporting the
    // first as the second is what cost a full investigation, so the mapping
    // from raised error to remedy is asserted on errors the code actually
    // raises rather than on hand-written error values.
    const with_ecall = [_]TraceRow{ addiRow(1, 0x10000, 1, 42), ecallRow(2, 0x10004) };
    const broken_chain = [_]TraceRow{danglingAddiRow(1, 0x10000)};

    const admission = opcode_memory.deriveRegisterBoundary(&with_ecall);
    try std.testing.expectError(error.UnsupportedForProof, admission);
    const chain = opcode_memory.deriveRegisterBoundary(&broken_chain);
    try std.testing.expectError(error.InvalidRegisterAccessChain, chain);

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
    // residual to a relation -- but it can see that the statement compensates
    // no public-I/O tuples at all, which no witness can balance if the guest
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
// 4. Wiring
// ---------------------------------------------------------------------------

test "diagnostic hints: both raise sites still report before propagating" {
    // The regression that matters is deletion: the classifier and its messages
    // can be perfect and still tell nobody anything if the raise site stops
    // calling them. Textual because the alternative is a mutable redirect in
    // production library code, which is a worse trade for a check this cheap.
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
