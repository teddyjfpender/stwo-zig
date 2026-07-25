//! Typed public statement paired with the canonical terminal proof bundle.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Modulus = @import("stwo_core").fields.m31.Modulus;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const cpu = @import("../../../examples/xor.zig");

pub fn OutputFor(comptime Transaction: type) type {
    const Raw = Transaction.StarkStatementBundleOutput;
    return struct {
        statement: cpu.Statement,
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
    base_statement: cpu.Statement,
    raw_input: Transaction.StarkStatementBundleOutput,
) !OutputFor(Transaction) {
    var raw = raw_input;
    const statement = decodeStatement(
        base_statement,
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
    base_statement: cpu.Statement,
    words: []const u32,
) !cpu.Statement {
    if (words.len != 4) return error.InvalidStatement;
    for (words) |word| {
        if (word >= Modulus) return error.InvalidFieldElement;
    }
    var result = base_statement;
    result.claimed_sum = QM31.fromM31(
        M31.fromCanonical(words[0]),
        M31.fromCanonical(words[1]),
        M31.fromCanonical(words[2]),
        M31.fromCanonical(words[3]),
    );
    return result;
}

test "terminal claimed sum is canonical and typed" {
    const statement = try decodeStatement(
        .{ .log_size = 8, .log_step = 2, .offset = 3 },
        &.{ 1, 2, 3, 4 },
    );
    try std.testing.expectEqual(@as(u32, 8), statement.log_size);
    try std.testing.expectEqual(@as(u32, 2), statement.log_step);
    try std.testing.expectEqual(@as(usize, 3), statement.offset);
    for (
        statement.claimed_sum.toM31Array(),
        [_]u32{ 1, 2, 3, 4 },
    ) |actual, expected| {
        try std.testing.expectEqual(expected, actual.toU32());
    }
    try std.testing.expectError(
        error.InvalidFieldElement,
        decodeStatement(
            .{ .log_size = 8, .log_step = 2, .offset = 3 },
            &.{ 1, Modulus, 3, 4 },
        ),
    );
}
