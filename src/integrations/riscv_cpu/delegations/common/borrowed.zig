//! Explicit caller-owned main buffers. Shape/overlap admission precedes every
//! provider write; allocator identity is never substituted for ownership.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const air = @import("stwo_riscv_frontend").rv64_air;
const C = @import("../../rv64_keccak_cpu.zig");
const Full = @import("../../rv64_full.zig");
const K = @import("../keccak/sources.zig");
const S = @import("../secp256k1/context.zig");
const Storage = air.crypto.main_storage;
pub const Arithmetic = struct { division: ?[]M = null, multiplication: ?[]M = null };
pub const Main = struct {
    arithmetic: Arithmetic = .{},
    keccak: ?K.MainBuffers = null,
    secp: S.MainBuffers = .{ null, null },
    pub fn validate(self: Main, a: std.mem.Allocator, cpu: *const Full.Trace, public: C.Public, setup: *const C.PreparedMaterials) !void {
        try setup.validate(public);
        try cpu.validateCommitAllocator(a);
        if (cpu.log_size != setup.base.log_size) return error.InvalidRv64FullMainPhase;
        if (cpu.main.len != (setup.base.plan.main_count + air.full.frame.widthWithControl(public.execution_profile, public.control_policy)) * cpu.domainSize()) return error.InvalidRv64FullMainPhase;
        if ((self.arithmetic.division != null) != (setup.division_fixed != null) or (self.arithmetic.multiplication != null) != (setup.multiplication_fixed != null) or (self.keccak != null) != (setup.crypto != null)) return error.InvalidBorrowedServiceBuffers;
        if (cpu.service_calls.len != public.keccak_calls) return error.InvalidBorrowedServiceBuffers;
        const actual_secp: [2]usize = if (cpu.secp) |journal| .{ journal.rows[0].len, journal.rows[1].len } else .{ 0, 0 };
        for (actual_secp, public.secp.counts()) |actual, expected| if (actual != expected) return error.InvalidBorrowedServiceBuffers;
        var slices: [12]Storage.Slice = undefined;
        var n: usize = 0;
        if (self.arithmetic.division) |main| add(&slices, &n, .{ .values = main, .cells = air.arithmetic.division.layout.MAIN * (@as(usize, 1) << @intCast(setup.division_log)) });
        if (self.arithmetic.multiplication) |main| add(&slices, &n, .{ .values = main, .cells = air.arithmetic.multiplication.layout.MAIN * (@as(usize, 1) << @intCast(setup.multiplication_log)) });
        if (self.keccak) |main| {
            try main.validate(public.keccak_calls, public.first_call_id, setup.keccak_log, setup.bridge_log);
            for (main.slices(setup.keccak_log, setup.bridge_log)) |slice| add(&slices, &n, slice);
        }
        for (self.secp, public.secp.groups(), 0..) |main, group, k| {
            if ((main != null) != (group.roster == .present)) return error.InvalidBorrowedServiceBuffers;
            if (main) |buffer| {
                try buffer.validate(group.geometry, if (k == 0) .add else .double, group.calls, group.first_id);
                for (buffer.slices(group.geometry)) |slice| add(&slices, &n, slice);
            }
        }
        const buffers = slices[0..n];
        try Storage.validate(buffers);
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.main));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.main_backing));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.state_metadata));
        try Storage.exclude(buffers, cpu.lookup_metadata);
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.rom_indices));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.rom_counts));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.and_counts));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.shift_counts));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.memory_clocks));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.service_calls));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.statement.cells));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.statement.program.words));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(cpu.statement.program.addresses));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(setup.base.program.rows));
        try Storage.exclude(buffers, std.mem.sliceAsBytes(setup.base.program.decoded));
        if (cpu.secp) |journal| for (journal.rows) |rows| {
            try Storage.exclude(buffers, std.mem.sliceAsBytes(rows));
        };
        const fixed = try setup.fixedColumns(a);
        defer a.free(fixed);
        for (fixed) |column| try Storage.exclude(buffers, std.mem.sliceAsBytes(column.values));
    }
};
fn add(out: *[12]Storage.Slice, at: *usize, slice: Storage.Slice) void {
    out[at.*] = slice;
    at.* += 1;
}
