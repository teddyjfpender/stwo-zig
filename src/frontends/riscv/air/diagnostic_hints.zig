//! The bridge from a rejection to the tool that explains it.
//!
//! This frontend has unusually good diagnostics -- per-relation sums,
//! per-relation tuples, public-value dumps, and an independent Python AIR
//! satisfaction checker -- and until this module existed, no failure said so.
//! Rich diagnostics nobody is told about are close to no diagnostics: two
//! multi-hour investigations were spent rediscovering tooling that was already
//! installed alongside the binary that produced the failure.
//!
//! The rule this module encodes: an error that a human is expected to act on
//! must name (a) the cause in the vocabulary of the thing that went wrong, and
//! (b) a command that narrows it further. Error *values* stay stable -- they
//! are asserted by name across the adversarial suites -- so the cause and the
//! command are carried alongside them, as text emitted at the raise site.
//!
//! ## Attribution and its limit
//!
//! A verifier holding only the statement, the proof and the interaction claim
//! *cannot* attribute a LogUp imbalance to a relation: a component's claimed
//! sum is one field element covering every relation that component touches, so
//! the residual is a scalar with no decomposition. `--relation-sums` can
//! attribute it because it re-derives the per-relation domain sums from the
//! retained commitment inputs (`prover/relation_diagnostic.zig`,
//! `air/relation_export.zig`). That asymmetry is exactly why the failure has to
//! *point* at the tool instead of trying to be it.
//!
//! The one shape the verifier can recognise on its own is a statement that
//! declares no public I/O. A guest that reads input or writes output emits
//! memory-access tuples the public side must consume; with empty `io_entries`
//! there is nothing to consume them, and the bus cannot balance no matter what
//! the witness does. That is a different failure from "some relation is
//! unbalanced" and gets its own message.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

/// Installed name of the host trace dumper.
///
/// `build_support/products/riscv_cpu.zig` installs the native build under this
/// name and the x86_64-linux-musl build under `TRACE_DUMP_STATIC`. The two were
/// once both installed as `riscv-trace-dump`, so a cross build silently
/// replaced the host binary and the next native run died with `Exec format
/// error`. A message that names the wrong one sends its reader to a binary that
/// cannot run, so these constants must be updated with that build file.
pub const TRACE_DUMP = "riscv-trace-dump";
/// Target-qualified name of the static trace dumper.
pub const TRACE_DUMP_STATIC = "riscv-trace-dump-x86_64-linux-musl";
/// Independent AIR-satisfaction checker, run over an exported trace.
pub const AIR_SATISFACTION = "scripts/air_satisfaction.py";

/// The complete invocations the hints below are allowed to name.
///
/// Named once rather than spelled per message, because the dumper's argument
/// grammar is not the obvious one and a hand-written invocation gets it wrong:
/// `--relation-sums` and `--relation-tuples` are *modes* whose value is the ELF
/// path, `--elf` is a third mode, and `src/tools/riscv/trace/main.zig` refuses
/// any invocation naming more than one mode (`mode_count != 1` ->
/// `error.ConflictingOptions`). The first draft of this module wrote
/// `--elf <elf> ... --relation-sums <out.json>`, which is two modes and an
/// output path the tool would not accept -- a hint that does not run is worse
/// than none, because it reads as authoritative.
///
/// `src/tests/riscv/diagnostic_hints_test.zig` re-derives the tool's flag and
/// mode sets from that source file and checks every constant here against them,
/// so a flag rename or a new mode fails a test rather than silently invalidating
/// advice. It lives outside this package because the dumper does too.
pub const DUMP_TRACE = TRACE_DUMP ++ " --elf <elf> --input <input>";
pub const DUMP_SUMS = TRACE_DUMP ++ " --relation-sums <elf> --input <input>";
pub const DUMP_TUPLES = TRACE_DUMP ++ " --relation-tuples <elf> --input <input>";
pub const CHECK_AIR = "python3 " ++ AIR_SATISFACTION;

/// Every dumper invocation this module publishes, for the grammar check.
pub const INVOCATIONS = [_][]const u8{ DUMP_TRACE, DUMP_SUMS, DUMP_TUPLES };

/// Why a rejection happened, at the granularity a reader can act on.
///
/// Deliberately coarser than the error set: several distinct error values share
/// one remedy, and one error value (`LogupSumNonZero`) covers two very
/// different remedies. The cause is what selects the message.
pub const Cause = enum {
    /// An execution-only opcode reached the prover. An admission failure, not
    /// a witness failure.
    unsupported_opcode,
    /// A representable trace's register source-before-destination chain does
    /// not close. A witness failure.
    register_access_chain,
    /// Global LogUp cancellation failed and the statement declares no public
    /// I/O at all.
    logup_no_public_io,
    /// Global LogUp cancellation failed with public I/O present, so which
    /// relation is unbalanced needs the per-relation dump.
    logup_unattributed,
};

/// The remediation text for a cause. Every one names a runnable command.
pub fn hint(cause: Cause) []const u8 {
    return switch (cause) {
        .unsupported_opcode => "an execution-only opcode (ECALL/EBREAK) reached the prover: this is an admission " ++
            "failure in the caller, not a witness defect. A proven run must end on the halt " ++
            "flag or a self-loop. List what the run actually retired with `" ++
            DUMP_TRACE ++ "`.",
        .register_access_chain => "a proof-representable trace's register source-before-destination chain does not " ++
            "close, so the memory_access bus cannot balance. Isolate the offending tuples " ++
            "with `" ++ DUMP_TUPLES ++ "` and cross-check the committed rows with `" ++
            CHECK_AIR ++ "`.",
        .logup_no_public_io => "IO relation unbalanced is the likely cause: the statement declares no public I/O, so " ++
            "a guest that reads input or writes output emits memory-access tuples nothing " ++
            "consumes, and the bus cannot cancel for any witness. Prove through the entry " ++
            "point that takes public data derived from the run, then confirm the per-relation " ++
            "sums with `" ++ DUMP_SUMS ++ "`.",
        .logup_unattributed => "one relation bus is unbalanced; the residual alone does not say which, because a " ++
            "component's claimed sum covers every relation it touches. Isolate the relation " ++
            "with `" ++ DUMP_SUMS ++ "`, list the offending tuples with `" ++ DUMP_TUPLES ++
            "`, and cross-check with `" ++ CHECK_AIR ++ "`.",
    };
}

/// Which LogUp message answers this failure.
///
/// `declares_public_io` is read off the statement's `io_entries`: false means
/// the statement claims the run neither consumed input nor produced output.
pub fn classifyLogup(declares_public_io: bool) Cause {
    return if (declares_public_io) .logup_unattributed else .logup_no_public_io;
}

/// Which register-boundary message answers this failure.
///
/// The two errors are distinct causes with distinct remedies and must not be
/// conflated: reporting an inadmissible opcode as a broken access chain points
/// the reader at witness generation for a defect that lives in opcode
/// admission, which is precisely the misdirection that cost a full
/// investigation.
pub fn classifyRegisterBoundary(err: anyerror) Cause {
    return switch (err) {
        error.UnsupportedForProof => .unsupported_opcode,
        else => .register_access_chain,
    };
}

/// Emit the register-boundary diagnostic. Returns nothing: the caller still
/// propagates the error value, which is what callers match on.
pub fn reportRegisterBoundary(err: anyerror) void {
    emit("riscv prove: register boundary derivation failed ({s}): {s}\n", .{
        @errorName(err),
        hint(classifyRegisterBoundary(err)),
    });
}

/// Emit the global-cancellation diagnostic, including the residual so a reader
/// can tell a wrong-by-one-tuple failure from a structurally absent bus.
pub fn reportLogupImbalance(residual: QM31, declares_public_io: bool) void {
    const coords = residual.toM31Array();
    emit(
        "riscv verify: global LogUp relations do not cancel " ++
            "(residual [{d}, {d}, {d}, {d}]): {s}\n",
        .{
            coords[0].v,
            coords[1].v,
            coords[2].v,
            coords[3].v,
            hint(classifyLogup(declares_public_io)),
        },
    );
}

/// One line to stderr, in every optimization mode.
///
/// Deliberately not `std.log`. Every level below `.err` is compiled out at
/// `-Doptimize=ReleaseFast`, which is the exact build whose failures cost the
/// investigations this module exists to prevent -- so a `warn` would be absent
/// where it matters most. `.err` survives ReleaseFast but Zig's test runner
/// fails any test that logs at that level, and the adversarial suites drive
/// these two paths on purpose, dozens of times per process: a hint that turns
/// every fail-closed regression test red is not a hint anyone would keep.
///
/// One line per failure, so a suite that provokes many stays greppable.
fn emit(comptime format: []const u8, args: anytype) void {
    std.debug.print(format, args);
}

// The pins for this module live in `diagnostic_hints_test.zig`, beside it. They
// used to live in `src/tests/riscv/`, reaching back across the package boundary
// with `@embedFile`, because no gate compiled a `test` written in this package.
// That is fixed: `test-riscv-cpu-product` and the `riscv_frontend` lane both run
// this package's tests now, so a pin belongs next to what it pins.
