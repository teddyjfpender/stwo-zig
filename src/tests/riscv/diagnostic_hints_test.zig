//! Whether the RISC-V frontend's diagnostic hints name invocations the trace
//! dumper actually accepts.
//!
//! The hints themselves -- their text, their cause attribution, and the fact
//! that both raise sites emit them -- are pinned inside the package that owns
//! them, in `src/frontends/riscv/air/diagnostic_hints_test.zig`. Those pins used
//! to live here, reaching into that package with
//! `@embedFile("../../frontends/riscv/air/opcode_memory.zig")`, because no gate
//! compiled a `test` written inside the frontend module (issue #152 item 11).
//! The reasoning was sound -- a pin that does not run is not a pin -- but the
//! embed crossed a package boundary and `scripts/check_package_workspace.py`
//! rejected it. The frontend's tests now run under `test-riscv-cpu-product`, so
//! those pins went home and this file kept only what it is uniquely placed to
//! check.
//!
//! What is left is a *cross-package* agreement that neither side can verify
//! alone: `air/diagnostic_hints.zig` publishes complete shell invocations, and
//! `src/tools/riscv/trace/main.zig` decides which invocations exist. This module
//! sees both, so it re-derives the dumper's flag and mode sets from the dumper's
//! own source and checks every published invocation against them.
//!
//! This is not theoretical. The first draft of the hints advertised
//! `--elf <elf> ... --relation-sums <out.json>`; the dumper rejects that with
//! `error.ConflictingOptions`, because `--relation-sums` is itself a mode whose
//! value is the ELF path. A hint that cannot be pasted into a shell is worse
//! than silence, since it reads as authoritative.
//!
//! Also pinned here, for the same reason: the dumper's *installed* names,
//! against the build file that installs them. Naming the wrong one sends a
//! reader to a binary that cannot run -- the concrete cost of issue #152 item 6a,
//! where a cross build replaced the host dumper and the next native run died
//! with `Exec format error`.

const std = @import("std");

const frontend = @import("stwo_riscv_frontend");
const hints = frontend.air.diagnostic_hints;

/// The trace dumper's own source. Embedded rather than read from disk so the
/// grammar check has no working-directory premise, and so a flag rename lands
/// here at compile time. `src/tools/riscv/trace` is owned by no package, so this
/// embed stays inside the aggregate module that owns the root test suite.
const DUMPER_SOURCE = @embedFile("../../tools/riscv/trace/main.zig");

/// The build file that installs the dumper, read at run time because it sits
/// outside this module's directory. Tests run from the repository root.
const BUILD_FILE = "build_support/products/riscv_cpu.zig";

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
