//! Typed State Machine v2 statement paired with the terminal proof bundle.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Modulus = @import("stwo_core").fields.m31.Modulus;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const cpu = @import("../../../examples/state_machine.zig");
const input = @import("../../../examples/state_machine/input.zig");

pub fn OutputFor(comptime Transaction: type) type {
    const Raw = Transaction.StarkStatementBundleOutput;
    return struct {
        statement: cpu.PreparedStatement,
        bundle: @FieldType(Raw, "bundle"),
        verdict: @FieldType(Raw, "verdict"),

        pub fn deinit(
            self: *@This(),
            allocator: std.mem.Allocator,
        ) void {
            self.bundle.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn fromRaw(
    comptime Transaction: type,
    allocator: std.mem.Allocator,
    request: input.Request,
    raw_input: Transaction.StarkStatementBundleOutput,
) !OutputFor(Transaction) {
    var raw = raw_input;
    const statement = decodeStatement(
        request,
        raw.statement_words,
    ) catch |err| {
        raw.deinit(allocator);
        return err;
    };
    allocator.free(raw.statement_words);
    return .{
        .statement = statement,
        .bundle = raw.bundle,
        .verdict = raw.verdict,
    };
}

pub fn decodeStatement(
    request: input.Request,
    words: []const u32,
) !cpu.PreparedStatement {
    if (words.len != 8) return error.InvalidStatement;
    for (words) |word| {
        if (word >= Modulus) return error.InvalidFieldElement;
    }
    const transitions = try cpu.transitionStates(
        request.log_n_rows,
        request.initial_state,
    );
    return .{
        .public_input = .{
            request.initial_state,
            transitions.final,
        },
        .stmt0 = .{
            .n = request.log_n_rows,
            .m = request.log_n_rows - 1,
        },
        .stmt1 = .{
            .x_axis_claimed_sum = decodeSecure(words[0..4]),
            .y_axis_claimed_sum = decodeSecure(words[4..8]),
        },
    };
}

fn decodeSecure(words: *const [4]u32) QM31 {
    return QM31.fromM31(
        M31.fromCanonical(words[0]),
        M31.fromCanonical(words[1]),
        M31.fromCanonical(words[2]),
        M31.fromCanonical(words[3]),
    );
}

test "terminal State v2 claimed sums are canonical and typed" {
    const request = input.Request{
        .log_n_rows = 8,
        .initial_state = .{
            M31.fromU64(9),
            M31.fromU64(3),
        },
    };
    const statement = try decodeStatement(
        request,
        &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
    );
    try std.testing.expectEqual(@as(u32, 8), statement.stmt0.n);
    try std.testing.expectEqual(@as(u32, 7), statement.stmt0.m);
    try std.testing.expectEqual(
        request.initial_state,
        statement.public_input[0],
    );
    for (
        statement.stmt1.x_axis_claimed_sum.toM31Array(),
        [_]u32{ 1, 2, 3, 4 },
    ) |actual, expected| {
        try std.testing.expectEqual(expected, actual.toU32());
    }
    for (
        statement.stmt1.y_axis_claimed_sum.toM31Array(),
        [_]u32{ 5, 6, 7, 8 },
    ) |actual, expected| {
        try std.testing.expectEqual(expected, actual.toU32());
    }
    try std.testing.expectError(
        error.InvalidFieldElement,
        decodeStatement(
            request,
            &.{ 1, 2, 3, 4, 5, Modulus, 7, 8 },
        ),
    );
}
