//! Transfers existing per-role MAIN allocations into one PCS ownership bundle.
//! All validation/allocation precedes transfer. No wide witness is copied or
//! rebuilt. AND/SHIFT multiplicities retain their small generator input copy.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const Source = @import("sources.zig").Source;
const Role = @import("setup.zig").Role;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const sameAllocator = front.rv64_air.memory.ownership.same;

pub const Commit = struct {
    columns: []Column,
    backings: [][]M,
    /// Only until handed to PCS, which consumes this bundle on every path.
    pub fn deinit(self: Commit, a: std.mem.Allocator) void {
        for (self.backings) |buffer| a.free(buffer);
        a.free(self.backings);
        a.free(self.columns);
    }
};

fn matrix(s: *Source, role: Role) *[]M {
    return switch (role) {
        .cpu => &s.cpu.main,
        .rom => &s.rom.main,
        .alu => &s.alu.main,
        .binary => &s.binary.main,
        .shift => &s.shift.main,
        .jalr => &s.jalr.main,
        .division => &s.division.main,
        .multiplication => &s.multiplication.main,
        .and_table => &s.and_table.main,
        .shift_table => &s.shift_table.main,
        .range16 => &s.range16.main,
        .range8 => &s.range8.main,
        .ls => &s.memory.ls.main,
        .ls_tail => &s.memory.ls_tail.?.main,
        .initial => &s.memory.initial.main,
        .terminal => &s.memory.terminal.main,
        .selection => &s.memory.selection.main,
        .boundary => unreachable,
    };
}
fn copied(role: Role) bool {
    return role == .and_table or role == .shift_table;
}

pub fn take(s: *Source) !Commit {
    if (s.claims != null) return error.InvalidExecutionMainOwnershipPhase;
    const a = s.allocator;
    inline for (.{ "cpu", "rom", "alu", "binary", "shift", "jalr", "division", "multiplication", "and_table", "shift_table", "range16", "range8" }) |name| {
        if (!sameAllocator(a, @field(s, name).allocator)) return error.ExecutionMainAllocatorMismatch;
    }
    inline for (.{ "ls", "initial", "terminal", "selection" }) |name| {
        if (!sameAllocator(a, @field(s.memory, name).allocator)) return error.ExecutionMainAllocatorMismatch;
    }
    if (!s.alu.owns_main or !s.binary.owns_main or !s.shift.owns_main or
        !s.division.owns_main or !s.multiplication.owns_main or !s.memory.ls.owns_main or
        !s.memory.initial.owns_main or !s.memory.terminal.owns_main) return error.BorrowedExecutionMain;
    if (s.memory.ls_tail) |tail| {
        if (!sameAllocator(a, tail.allocator)) return error.ExecutionTailAllocatorMismatch;
        if (!tail.owns_main) return error.BorrowedExecutionMain;
    }
    const columns = try s.columns(a, 1);
    errdefer a.free(columns);
    const shapes = s.materials.shapes();
    var count: usize = 0;
    for (shapes) |shape| if (shape.widths[1] != 0) {
        count += 1;
    };
    const backings = try a.alloc([]M, count);
    errdefer a.free(backings);
    // Ensure unique disjoint allocation ranges before the success-only move.
    var at: usize = 0;
    for (shapes) |shape| {
        if (shape.widths[1] == 0) continue;
        const data = matrix(s, shape.role).*;
        const end = try std.math.add(usize, @intFromPtr(data.ptr), try std.math.mul(usize, data.len, @sizeOf(M)));
        for (backings[0..at]) |prior| {
            const prior_end = try std.math.add(usize, @intFromPtr(prior.ptr), try std.math.mul(usize, prior.len, @sizeOf(M)));
            if (@intFromPtr(data.ptr) < prior_end and @intFromPtr(prior.ptr) < end) return error.AliasedExecutionMain;
        }
        backings[at] = data;
        at += 1;
    }
    var and_copy: ?[]M = null;
    errdefer if (and_copy) |v| a.free(v);
    var shift_copy: ?[]M = null;
    errdefer if (shift_copy) |v| a.free(v);
    and_copy = try a.dupe(M, s.and_table.main);
    shift_copy = try a.dupe(M, s.shift_table.main);
    // No fallible work remains. Each original allocation moves exactly once.
    at = 0;
    for (shapes) |shape| {
        if (shape.widths[1] == 0) continue;
        if (copied(shape.role)) {
            backings[at] = if (shape.role == .and_table) and_copy.? else shift_copy.?;
            const n = @as(usize, 1) << @intCast(shape.log);
            for (columns[shape.offsets[1]..][0..shape.widths[1]], 0..) |*column, i|
                column.values = backings[at][i * n ..][0..n];
        } else matrix(s, shape.role).* = &.{};
        at += 1;
    }
    s.alu.owns_main = false;
    s.binary.owns_main = false;
    s.shift.owns_main = false;
    if (s.materials.shape(.division).widths[1] != 0) s.division.owns_main = false;
    s.multiplication.owns_main = false;
    s.memory.ls.owns_main = false;
    if (s.materials.shape(.ls_tail).widths[1] != 0) {
        if (s.memory.ls_tail) |*tail| tail.owns_main = false;
    }
    s.memory.initial.owns_main = false;
    s.memory.terminal.owns_main = false;
    return .{ .columns = columns, .backings = backings };
}
