//! Pure-P2 post-seal retirement only. Legacy source/generator defaults remain
//! unchanged. Local binding uses the retained packed SHIFT multiplicities;
//! global RAM uses LS tuple metadata, never these duplicate raw fixed masks.
const std = @import("std");
const R = @import("../word16_global_execution/services/roster.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = @import("stwo_core").fields.m31.M31;
const SHIFT_ROWS = A.word16_v1.shift_word_packed_experiment.table.SIZE;
const SHIFT_FACTS = A.word16_v1.shift_word_experiment.table.SIZE;
pub const Retired = struct { raw_ls_fixed_bytes: usize, shift_histogram_bytes: usize };
fn checkLs(source: anytype) !usize {
    if (source.main.len != 0 or source.fixed.len != 3 * (@as(usize, 1) << @intCast(source.log_size))) return error.OpSourceAuxiliaryPhase;
    return std.mem.sliceAsBytes(source.fixed).len;
}
fn freeLs(source: anytype) void {
    source.allocator.free(source.fixed);
    source.fixed = &.{};
}
fn validateShift(head: []const u64, tail: []const u64, main: []const M) !void {
    if (head.len != SHIFT_FACTS or (tail.len != 0 and tail.len != SHIFT_FACTS) or main.len != 16 * SHIFT_ROWS) return error.OpSourceAuxiliaryPhase;
    for (0..SHIFT_FACTS) |i| {
        const sum = try std.math.add(u64, head[i], if (tail.len == 0) 0 else tail[i]);
        const physical = A.word16_execution.layout.physical(i / 16, A.word16_v1.shift_word_packed_experiment.table.LOG);
        if (sum != main[(i % 16) * SHIFT_ROWS + physical].v) return error.OpSourceAuxiliaryMultiplicity;
    }
}
/// All shape/content checks precede frees: an invalid retained table leaves
/// source ownership untouched. MAIN was already committed and is not rebuilt.
pub fn retire(source: *R.Sources) !Retired {
    const core = &source.core;
    var ls_bytes = try checkLs(&core.memory.ls);
    if (core.memory.ls_tail) |*tail| ls_bytes = try std.math.add(usize, ls_bytes, try checkLs(tail));
    for (&source.ls_dword) |*entry| {
        if (entry.*) |*dword| ls_bytes = try std.math.add(usize, ls_bytes, try checkLs(dword));
    }
    const head = core.shift.shift_counts;
    const tail = if (core.tails.shift) |s| s.shift_counts else &.{};
    if (core.shift.main.len != 0 or head.len != SHIFT_FACTS or (tail.len != 0 and tail.len != SHIFT_FACTS) or core.shift_table.main.len != 16 * SHIFT_ROWS) return error.OpSourceAuxiliaryPhase;
    if (core.tails.shift) |s| if (s.main.len != 0) return error.OpSourceAuxiliaryPhase;
    try validateShift(head, tail, core.shift_table.main);
    const shift_bytes = try std.math.add(usize, std.mem.sliceAsBytes(head).len, std.mem.sliceAsBytes(tail).len);
    freeLs(&core.memory.ls);
    if (core.memory.ls_tail) |*s| freeLs(s);
    for (&source.ls_dword) |*entry| if (entry.*) |*s| freeLs(s);
    core.shift.allocator.free(core.shift.shift_counts);
    core.shift.shift_counts = &.{};
    if (core.tails.shift) |*s| {
        s.allocator.free(s.shift_counts);
        s.shift_counts = &.{};
    }
    return .{ .raw_ls_fixed_bytes = ls_bytes, .shift_histogram_bytes = shift_bytes };
}

test "OP source retirement packed shift authority refuses mismatch before ownership changes" {
    const a = std.testing.allocator;
    const head = try a.alloc(u64, SHIFT_FACTS);
    defer a.free(head);
    const tail = try a.alloc(u64, SHIFT_FACTS);
    defer a.free(tail);
    const main = try a.alloc(M, 16 * SHIFT_ROWS);
    defer a.free(main);
    @memset(head, 0);
    @memset(tail, 0);
    @memset(main, M.zero());
    const index = 29999;
    const at = (index % 16) * SHIFT_ROWS + A.word16_execution.layout.physical(index / 16, A.word16_v1.shift_word_packed_experiment.table.LOG);
    head[index] = 7;
    tail[index] = 3;
    main[at] = M.fromCanonical(10);
    try validateShift(head, tail, main);
    main[at] = M.fromCanonical(11);
    try std.testing.expectError(error.OpSourceAuxiliaryMultiplicity, validateShift(head, tail, main));
    try std.testing.expectEqual(@as(u64, 7), head[index]);
    try std.testing.expectEqual(@as(u64, 3), tail[index]);
    head[index] = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, validateShift(head, tail, main));
}
