//! Canonical cartridge bus cycles for scheduler events.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("../cartridge/mod.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const cartridge_access_component = @import("cartridge_access_component.zig");
const execution = @import("execution.zig");
const scheduler = @import("scheduler.zig");

pub const Cycle = struct {
    bus: runner.BusCycle = .{ .address = 0, .value = 0, .action = .idle },
    access: ?runner.cartridge_memory.Access = null,
    mapper_before: cartridge.State = .{},
    mapper_after: cartridge.State = .{},
};

pub const ValidatedStep = struct {
    result: machine.CartridgeStepResult,
    cycles: [runner.MAX_BUS_CYCLES]Cycle,
    count: u3,

    pub fn init(result: machine.CartridgeStepResult) !ValidatedStep {
        _ = scheduler.ValidatedStep.init(result) catch
            return error.InvalidSchedulerStep;
        var out = ValidatedStep{
            .result = result,
            .cycles = [_]Cycle{.{}} ** runner.MAX_BUS_CYCLES,
            .count = result.m_cycles,
        };
        switch (result.event) {
            .instruction => {
                const trace = cartridge_access.ValidatedStep.init(
                    result.instruction orelse
                        return error.InvalidCartridgeAccess,
                ) catch return error.InvalidCartridgeAccess;
                for (0..result.m_cycles) |cycle| {
                    out.cycles[cycle] = .{
                        .bus = trace.trace.instruction.cycles[cycle],
                        .access = trace.trace.accesses[cycle],
                        .mapper_before = trace.mapper_before[cycle],
                        .mapper_after = trace.mapper_after[cycle],
                    };
                }
            },
            .halt_idle, .halt_wake => out.cycles[0] = .{
                .mapper_before = result.mapper_before,
                .mapper_after = result.mapper_after,
            },
            .interrupt_service => {
                var mapper = result.mapper_before;
                for (result.service.activeCycles(), 0..) |
                    service_cycle,
                    cycle,
                | {
                    if (service_cycle.access) |access| {
                        out.cycles[cycle] = .{
                            .bus = .{
                                .address = access.logical_address,
                                .value = access.value,
                                .action = switch (access.action) {
                                    .read => .read,
                                    .write => .write,
                                },
                            },
                            .access = access,
                            .mapper_before = access.mapper_before,
                            .mapper_after = access.mapper_after,
                        };
                        mapper = access.mapper_after;
                    } else {
                        out.cycles[cycle] = .{
                            .mapper_before = mapper,
                            .mapper_after = mapper,
                        };
                    }
                }
                if (!std.meta.eql(mapper, result.mapper_after))
                    return error.DisconnectedMapperState;
            },
        }
        return out;
    }

    pub fn activeCycles(self: *const ValidatedStep) []const Cycle {
        return self.cycles[0..self.count];
    }
};

pub fn columnsForCycle(
    step: ValidatedStep,
    cycle: usize,
) [cartridge_access.N_MAIN_COLUMNS]M31 {
    std.debug.assert(cycle < step.count);
    const item = step.cycles[cycle];
    return cartridge_access.columnsForBusCycle(
        item.bus,
        item.access,
        item.mapper_before,
        item.mapper_after,
    );
}

pub fn columns(
    step: ValidatedStep,
) [cartridge_access_component.N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} **
        cartridge_access_component.N_MAIN_COLUMNS;
    for (0..execution.N_BUS_CYCLES) |cycle| {
        const source = if (cycle < step.count)
            columnsForCycle(step, cycle)
        else
            cartridge_access.inactiveColumns();
        const offset = cycle * cartridge_access.N_MAIN_COLUMNS;
        @memcpy(
            out[offset..][0..cartridge_access.N_MAIN_COLUMNS],
            &source,
        );
    }
    return out;
}
