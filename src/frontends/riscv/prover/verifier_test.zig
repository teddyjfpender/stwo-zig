//! Which LogUp remedy the verifier asks for, and why it may not be a constant.
//!
//! `LogupSumNonZero` covers two failures with very different remedies: a
//! statement that compensates no public-I/O tuples at all (no witness can balance
//! it, and the fix is to prove through the entry point that takes public data),
//! and a residual on some relation the verifier cannot name (the fix is to dump
//! the per-relation sums). Splitting the *error* was rejected -- an error set is a
//! protocol surface -- so the implementer's substitute is that the verifier reads
//! the statement and selects the cause. That selection is the whole of issue #152
//! item 3 on the verify side: with it replaced by a constant the error still
//! names a cause, still names a command, and names the wrong one, which is worse
//! than naming none.
//!
//! A wave-2 verifier replaced the selection with the literal `true` and no test in
//! the repository went red.
//!
//! ## Why the wiring half is structural
//!
//! The behaviour is only observable on a failing verification, which needs a
//! proof, which needs a prover engine. This package has none -- `mod.zig`'s
//! dependencies are `stwo_core`, `stwo_prover_api` and `stwo_prover_engine`, and
//! concrete backend selection belongs to an integration -- so a test here cannot
//! reach the branch. Splitting the obligation instead:
//!
//!   * the *selection* is behavioural, driven below on the predicate the verifier
//!     reads and the reporter it feeds, and observed on stderr; and
//!   * the *wiring* -- that the verifier passes that predicate and not a constant
//!     -- is read off the verifier's own source.
//!
//! Together they close the mutation. The same file's sibling
//! `air/diagnostic_hints_test.zig` pins that the report is reached from the
//! cancellation check's error path at all.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;

const hints = @import("../air/diagnostic_hints.zig");
const public_data = @import("../air/public_data.zig");

/// The verifier's own text. Embedded rather than read from disk so the wiring
/// check has no working-directory premise and a moved call fails at compile time.
const VERIFIER_SOURCE = @embedFile("verifier.zig");

/// The protocol-selected predicate the verifier must hand the reporter.
const SELECTION = "Protocol.declaresPublicIo(&statement)";
const V1_SELECTION = "value.public_data.declaresPublicIo()";
const V2_SELECTION = "value.declaresPublicIo() catch true";

/// Return the complete argument list of the `reportLogupImbalance` call.
///
/// Depth-matched rather than "find the next `)`": both arguments are themselves
/// calls, and a slice that stopped at the first close paren would silently drop
/// the tail of the second argument -- which is the argument under inspection, so
/// the check would then pass on text it never read.
fn reportArguments(source: []const u8) ![]const u8 {
    const call = std.mem.indexOf(u8, source, "reportLogupImbalance(") orelse
        return error.LogupReportCallMissing;
    const open = call + "reportLogupImbalance(".len;
    var depth: usize = 1;
    var index = open;
    while (index < source.len) : (index += 1) {
        switch (source[index]) {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if (depth == 0) return source[open..index];
            },
            else => {},
        }
    }
    return error.LogupReportCallNotClosed;
}

test "verifier: the LogUp remedy is selected from the statement, not fixed" {
    const arguments = try reportArguments(VERIFIER_SOURCE);
    if (std.mem.indexOf(u8, arguments, SELECTION) == null) {
        std.debug.print(
            "the LogUp report no longer selects its cause from the statement; it passes:\n{s}\n",
            .{arguments},
        );
        return error.LogupCauseNotSelectedFromStatement;
    }
    // Both protocol adapters must in turn derive the predicate from their
    // statement representation. This closes the generic-dispatch seam without
    // requiring the report call to know either statement layout.
    try std.testing.expect(std.mem.indexOf(u8, VERIFIER_SOURCE, V1_SELECTION) != null);
    try std.testing.expect(std.mem.indexOf(u8, VERIFIER_SOURCE, V2_SELECTION) != null);
    // A constant here is the mutation: the message would name one cause for both
    // failures and be confidently wrong on one of them.
    for ([_][]const u8{ "true", "false" }) |literal| {
        if (std.mem.indexOf(u8, arguments, literal) == null) continue;
        std.debug.print(
            "the LogUp report is passed the constant `{s}`:\n{s}\n",
            .{ literal, arguments },
        );
        return error.LogupCauseIsConstant;
    }
}

test "verifier: the fixture the wiring check reads still holds the call" {
    // Fails closed. The check above is a substring search, and a search over text
    // that no longer holds the call reports success.
    try std.testing.expect(VERIFIER_SOURCE.len > 1024);
    const arguments = try reportArguments(VERIFIER_SOURCE);
    try std.testing.expect(arguments.len != 0);
    // Balanced, so the slice is the whole argument list and not a prefix of it: a
    // truncated slice would hide whatever the dropped tail contained.
    try std.testing.expectEqual(
        std.mem.count(u8, arguments, "("),
        std.mem.count(u8, arguments, ")"),
    );
    // Both arguments are present, so a one-argument call cannot pass silently.
    try std.testing.expect(std.mem.indexOfScalar(u8, arguments, ',') != null);
    try std.testing.expect(std.mem.indexOf(u8, arguments, "public_boundary") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, VERIFIER_SOURCE, "verifyGlobalCancellation(") != null,
    );
}

test "verifier: the selected predicate reaches stderr as two different remedies" {
    // The behavioural half, on the exact expression the wiring check requires: a
    // statement that declares no public I/O must get the message about declaring
    // no public I/O, and one that declares some must get the unattributed message.
    // Both are observed on stderr rather than compared as enum tags, because a
    // cause nobody receives is the defect this pin exists for.
    const allocator = std.testing.allocator;
    const input = [_]u32{7};

    const silent = statementWith(&.{}, &.{});
    try std.testing.expect(!silent.declaresPublicIo());
    const quiet = try captureReport(allocator, &silent);
    defer allocator.free(quiet);
    try std.testing.expect(
        std.mem.indexOf(u8, quiet, hints.hint(.logup_no_public_io)) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, quiet, hints.hint(.logup_unattributed)) == null,
    );

    const speaking = statementWith(&input, &.{});
    try std.testing.expect(speaking.declaresPublicIo());
    const loud = try captureReport(allocator, &speaking);
    defer allocator.free(loud);
    try std.testing.expect(
        std.mem.indexOf(u8, loud, hints.hint(.logup_unattributed)) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, loud, hints.hint(.logup_no_public_io)) == null,
    );
}

/// Report an imbalance for `statement`'s public data and return what it wrote.
///
/// The second argument is written exactly as the verifier writes it, so this
/// exercises the composition the wiring check requires rather than a paraphrase.
fn captureReport(
    allocator: std.mem.Allocator,
    statement_public_data: *const public_data.PublicData,
) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var file = try tmp.dir.createFile("stderr.txt", .{});
        defer file.close();
        const saved = try std.posix.dup(std.posix.STDERR_FILENO);
        defer std.posix.close(saved);
        try std.posix.dup2(file.handle, std.posix.STDERR_FILENO);
        // Restored before `saved` closes: `defer` unwinds last-declared-first.
        defer std.posix.dup2(saved, std.posix.STDERR_FILENO) catch {};
        hints.reportLogupImbalance(
            QM31.fromU32Unchecked(7, 0, 0, 0),
            statement_public_data.declaresPublicIo(),
        );
    }
    return tmp.dir.readFileAlloc(allocator, "stderr.txt", 1 << 16);
}

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
