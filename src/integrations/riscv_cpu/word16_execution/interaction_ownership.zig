//! Success-only transfer of the existing seventeen INTER allocations to PCS.
//! Every generator has finished and published its claims before this handoff;
//! no generator needs an interaction input copy and no values are rebuilt.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const Source = @import("sources.zig").Source;
const Role = @import("setup.zig").Role;
const M = core.fields.m31.M31;
pub const Commit = @import("main_ownership.zig").Commit;
const sameAllocator = front.rv64_air.memory.ownership.same;

fn matrix(s: *Source, role: Role) *[]M {
    return switch (role) {
        .cpu => &s.cpu.interaction,
        .rom => &s.rom.interaction,
        .boundary => &s.boundary,
        .alu => &s.alu.interaction,
        .binary => &s.binary.interaction,
        .shift => &s.shift.interaction,
        .jalr => &s.jalr.interaction,
        .division => &s.division.interaction,
        .multiplication => &s.multiplication.interaction,
        .and_table => &s.and_table.interaction,
        .shift_table => &s.shift_table.interaction,
        .range16 => &s.range16.interaction,
        .range8 => &s.range8.interaction,
        .ls => &s.memory.ls.interaction,
        .initial => &s.memory.initial.interaction,
        .terminal => &s.memory.terminal.interaction,
        .selection => &s.memory.selection.interaction,
    };
}

pub fn take(s: *Source) !Commit {
    if (s.claims == null) return error.InvalidExecutionInteractionOwnershipPhase;
    const a = s.allocator;
    inline for (.{ "cpu", "rom", "alu", "binary", "shift", "jalr", "division", "multiplication", "and_table", "shift_table", "range16", "range8" }) |name| {
        if (!sameAllocator(a, @field(s, name).allocator)) return error.ExecutionInteractionAllocatorMismatch;
    }
    inline for (.{ "ls", "initial", "terminal", "selection" }) |name| {
        if (!sameAllocator(a, @field(s.memory, name).allocator)) return error.ExecutionInteractionAllocatorMismatch;
    }
    const columns = try s.columns(a, 2);
    errdefer a.free(columns);
    const shapes = s.materials.shapes();
    var count: usize = 0;
    for (shapes) |shape| if (shape.widths[2] != 0) {
        count += 1;
    };
    const backings = try a.alloc([]M, count);
    errdefer a.free(backings);
    var at: usize = 0;
    for (shapes) |shape| {
        if (shape.widths[2] == 0) continue;
        const data = matrix(s, shape.role).*;
        const end = try std.math.add(usize, @intFromPtr(data.ptr), try std.math.mul(usize, data.len, @sizeOf(M)));
        for (backings[0..at]) |prior| {
            const prior_end = try std.math.add(usize, @intFromPtr(prior.ptr), try std.math.mul(usize, prior.len, @sizeOf(M)));
            if (@intFromPtr(data.ptr) < prior_end and @intFromPtr(prior.ptr) < end) return error.AliasedExecutionInteraction;
        }
        backings[at] = data;
        at += 1;
    }
    // No fallible work remains. The physical claims and narrow metadata stay
    // with Source; only these existing matrix allocations change owners.
    for (shapes) |shape| {
        if (shape.widths[2] != 0) matrix(s, shape.role).* = &.{};
    }
    return .{ .columns = columns, .backings = backings };
}
