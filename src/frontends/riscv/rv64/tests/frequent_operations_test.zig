const std = @import("std");
const F = @import("../frequent_operations.zig");
const R = @import("../retirement.zig").Retirement;
const Word = @import("../word.zig").Word;
const a = std.testing.allocator;
const x = F.Tuple{ .opcode = .ADD, .lhs = 1 << 48, .rhs = 9, .result = (1 << 48) + 9 };
const y = F.Tuple{ .opcode = .ADDW, .lhs = 1 << 48, .rhs = 9, .result = 9 };

test "frequent operation census counts exact ordered full width tuples and reports saturation honestly" {
    var census = try F.Census.init(a, 2);
    defer census.deinit();
    try census.observe(x);
    try census.observe(y);
    var other = x;
    other.lhs = 0;
    try census.observe(other);
    try census.observe(other);
    try census.observe(x);
    const s = try census.summary(a, 256);
    defer a.free(s.top);
    try std.testing.expectEqual(@as(u64, 5), s.eligible_operations);
    try std.testing.expectEqual(@as(usize, 2), s.retained_unique);
    try std.testing.expectEqual(@as(u64, 3), s.tracked_occurrences);
    try std.testing.expectEqual(@as(u64, 2), s.untracked_occurrences);
    try std.testing.expectEqual(@as(u64, 1), s.repeated_retained_operations);
    try std.testing.expectEqualDeep(x, s.top[0].tuple);
    try std.testing.expectEqual(@as(u64, 2), s.top[0].occurrences);
}

test "frequent operation keys select immediate operands and preserve W modes without control or memory tuples" {
    var row = std.mem.zeroes(R);
    row.opcode = .ADDI;
    row.lhs = Word.fromInt(1 << 48);
    row.rhs = Word.fromInt(123);
    row.immediate = Word.fromInt(std.math.maxInt(u64));
    row.result = Word.fromInt((1 << 48) - 1);
    const immediate = F.operation(row).?;
    try std.testing.expectEqual(std.math.maxInt(u64), immediate.rhs);
    try std.testing.expectEqual(@as(u64, 1 << 48), immediate.lhs);
    row.opcode = .ADD;
    try std.testing.expectEqual(@as(u64, 123), F.operation(row).?.rhs);
    row.opcode = .ADDW;
    try std.testing.expect(F.operation(row).?.opcode != immediate.opcode);
    inline for (.{ .AUIPC, .LD, .SD, .BEQ, .JALR, .ECALL }) |opcode| {
        row.opcode = opcode;
        try std.testing.expect(F.operation(row) == null);
    }
}

test "frequent operation accounting and owners survive every allocation failure and count overflow" {
    try std.testing.expectError(error.InvalidFrequentOperationLimit, F.Census.init(a, 0));
    try std.testing.expectError(error.InvalidFrequentOperationLimit, F.Census.init(a, F.MAX_ENTRIES + 1));
    try std.testing.checkAllAllocationFailures(a, construct, .{});
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var census = try F.Census.init(fail.allocator(), 2);
    defer census.deinit();
    try std.testing.expectError(error.OutOfMemory, census.observe(x));
    try std.testing.expectEqual(@as(u64, 0), census.eligible);
    try std.testing.expectEqual(@as(u64, 0), census.tracked);
    census.eligible = std.math.maxInt(u64);
    try std.testing.expectError(error.FrequentOperationCountOverflow, census.observe(x));
}
fn construct(allocator: std.mem.Allocator) !void {
    var census = try F.Census.init(allocator, 2);
    defer census.deinit();
    try census.observe(y);
    try census.observe(x);
    const s = try census.summary(allocator, 1);
    defer allocator.free(s.top);
    try std.testing.expectEqualDeep(x, s.top[0].tuple);
}
