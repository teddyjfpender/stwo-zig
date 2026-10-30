//! Independently derived, resident caller inventory for the proposed mixed
//! endpoint original. This is NOT an admission receipt or a complete AIR.
//! Existing arithmetic/program/state/table equations remain authoritative;
//! the old integer/WORD witness and its memory partition are deliberately absent.
const std = @import("std");
const core = @import("stwo_core");
const P = @import("blake3_ethereum_sha_profile.zig");
const Layout = @import("block_v7_caller_active_layout_v1.zig").Layout;
const Schedule = @import("block_v7_caller_active_schedule_v1.zig");
const Ram = @import("block_v8_caller_ram_projection_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
pub const production_active = false;
pub const VERSION: u32 = 1;
pub const Limits = struct {
    max_steps: u32 = 1 << 24,
    max_external_calls: u32 = 1 << 16,
    max_row_log: u32 = 24,
    max_columns: usize = 1 << 16,
    max_raw_cells: u64 = 1 << 30,
};
pub const Offsets = struct { arithmetic: usize = 0, program: usize, state: usize, tables: usize, ram: usize };
pub const Owned = struct {
    a: std.mem.Allocator,
    statement: P.admission.Statement,
    frame: @import("../air/block/memory_event.zig").Frame,
    steps: u32,
    layout: Layout,
    schedule: Schedule.Schedule,
    ram: Ram.Plan,
    interaction_logs: []u32,
    offsets: Offsets,
    arithmetic_main_columns: usize,
    halt_main_columns: usize,
    raw_fixed_main_cells: u64,
    interaction_cells: u64,
    digest: [32]u8,
    pub fn init(a: std.mem.Allocator, statement: *const P.admission.Statement, steps: u32, frame: @import("../air/block/memory_event.zig").Frame, limits: Limits) !Owned {
        if (steps == 0 or steps > (1 << 24) or steps > limits.max_steps or limits.max_row_log > 24 or limits.max_columns == 0 or limits.max_raw_cells == 0 or P.externalCount(statement) == 0 or P.externalCount(statement) > limits.max_external_calls) return error.InvalidEndpointCallerLimits;
        try Protocol.validateGeometry(statement, steps);
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, statement);
        const layout = try Layout.derive(statement, steps);
        var schedule = try Schedule.derive(a, statement, steps, frame);
        errdefer schedule.deinit();
        var ram = try Ram.Plan.derive(a, statement, steps, frame);
        errdefer ram.deinit();
        if (ram.descriptors.len != schedule.memory.len or ram.logical_ram_accesses != schedule.rw_events) return error.UntrustedEndpointCallerInventory;
        for (ram.descriptors, schedule.memory) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedEndpointCallerInventory;
        const program_count = try std.math.mul(usize, schedule.program.len, 4);
        const offsets = Offsets{ .program = layout.totals[2], .state = try std.math.add(usize, layout.totals[2], program_count), .tables = try std.math.add(usize, layout.totals[2], try std.math.mul(usize, program_count, 2)), .ram = try std.math.add(usize, layout.totals[2], try std.math.add(usize, try std.math.mul(usize, program_count, 2), try std.math.mul(usize, schedule.tables.len, 4))) };
        const width = try std.math.add(usize, offsets.ram, try std.math.mul(usize, ram.descriptors.len, 4));
        const halt_width = try std.math.mul(usize, ram.descriptors.len, 2);
        if (width > limits.max_columns or try std.math.add(usize, layout.totals[1], halt_width) > limits.max_columns or layout.totals[0] > limits.max_columns) return error.EndpointCallerColumnLimit;
        const logs = try a.alloc(u32, width);
        errdefer a.free(logs);
        var cursor: usize = 0;
        for (0..19) |i| if (layout.active[i]) {
            @memset(logs[cursor..][0..layout.widths[i][2]], layout.logs[i]);
            cursor += layout.widths[i][2];
        };
        if (cursor != offsets.program) return error.UntrustedEndpointCallerInventory;
        for (schedule.program, 0..) |slot, i| {
            @memset(logs[offsets.program + 4 * i ..][0..4], slot.log_size);
            @memset(logs[offsets.state + 4 * i ..][0..4], slot.log_size);
        }
        for (schedule.tables, 0..) |slot, i| @memset(logs[offsets.tables + 4 * i ..][0..4], slot.log_size);
        for (ram.descriptors, 0..) |slot, i| @memset(logs[offsets.ram + 4 * i ..][0..4], slot.log_size);
        var raw_cells: u64 = 0;
        for (schedule.fixed) |log| try addCells(&raw_cells, log, 1, limits);
        for (schedule.main) |log| try addCells(&raw_cells, log, 1, limits);
        for (ram.descriptors) |slot| try addCells(&raw_cells, slot.log_size, 2, limits);
        var interaction_cells: u64 = 0;
        for (logs) |log| try addCells(&interaction_cells, log, 1, limits);
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42384d43, VERSION, steps, @intFromEnum(Protocol.circuit_profile), @intFromEnum(frame.clock_frame), frame.cycle_count });
        channel.mixU64(frame.global_first_cycle);
        statement.ethereum.mixValidatedInto(&channel);
        try statement.sha.mixIntoForRecipe(&channel, Protocol.circuit_profile.localZeroCustody());
        layout.mix(&channel);
        ScheduleMix(&channel, &schedule);
        channel.mixRoot(ram.digest);
        for (logs) |log| channel.mixU32s(&.{log});
        channel.mixU64(halt_width);
        return .{ .a = a, .statement = statement.*, .frame = frame, .steps = steps, .layout = layout, .schedule = schedule, .ram = ram, .interaction_logs = logs, .offsets = offsets, .arithmetic_main_columns = layout.totals[1], .halt_main_columns = halt_width, .raw_fixed_main_cells = raw_cells, .interaction_cells = interaction_cells, .digest = channel.digestBytes() };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.interaction_logs);
        self.ram.deinit();
        self.schedule.deinit();
        self.* = undefined;
    }
};
fn ScheduleMix(channel: anytype, schedule: *const Schedule.Schedule) void {
    @import("block_v5_caller_fused_schedule_v1.zig").mix(channel, schedule);
}
fn addCells(total: *u64, log: u32, width: u64, limits: Limits) !void {
    if (log > limits.max_row_log) return error.EndpointCallerRowLimit;
    total.* = try std.math.add(u64, total.*, try std.math.mul(u64, @as(u64, 1) << @intCast(log), width));
    if (total.* > limits.max_raw_cells) return error.EndpointCallerCellLimit;
}
