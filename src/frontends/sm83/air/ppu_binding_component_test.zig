const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const binding = @import("ppu_binding.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");

test "PPU machine adapter covers instruction HALT and service M-cycles" {
    const instruction_trace = accessStep();
    const instruction = machine.CartridgeStepResult{
        .before = machineState(instruction_trace.instruction.before, 0, 0),
        .after = machineState(instruction_trace.instruction.after, 0, 0),
        .event = .instruction,
        .m_cycles = 1,
        .instruction = instruction_trace,
    };
    var trace = try binding.generateFromMachineExecution(
        std.testing.allocator,
        0,
        1,
        .{},
        &.{instruction},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), trace.rows.len);
    try std.testing.expectEqual(@as(u8, 0x22), trace.final_state.timing.lyc);
    var witness = try binding.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{instruction},
        0,
    );
    witness.deinit();

    const idle_before = machineState(.{ .halted = true }, 0, 1);
    const idle_after = idle_before;
    var wake_after = idle_after;
    wake_after.interrupt_flags = 1;
    wake_after.cpu.halted = false;
    const idle = machineResult(.halt_idle, idle_before, idle_after, 1);
    const wake = machineResult(.halt_wake, idle_after, wake_after, 1);
    var halted = try binding.generateFromMachineExecution(
        std.testing.allocator,
        1,
        3,
        .{},
        &.{ idle, wake },
    );
    defer halted.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 8), halted.rows.len);

    const service = interruptService(0xc102, false);
    const enabled = binding.State{
        .timing = .{
            .lcd_enabled = true,
            .coincidence = true,
            .lyc_interrupt_line = true,
        },
        .lcdc = 0x80,
    };
    var serviced = try binding.generateFromMachineExecution(
        std.testing.allocator,
        3,
        8,
        enabled,
        &.{service},
    );
    defer serviced.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 20), serviced.rows.len);
    try std.testing.expectEqual(@as(u16, 20), serviced.final_state.timing.dot);
    var halted_service = try binding.generateFromMachineExecution(
        std.testing.allocator,
        8,
        14,
        serviced.final_state,
        &.{interruptService(0xc102, true)},
    );
    defer halted_service.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 24), halted_service.rows.len);
    try std.testing.expectEqual(
        @as(u16, 44),
        halted_service.final_state.timing.dot,
    );
    serviced.rows[0].provenance = .detached;
    try std.testing.expectError(
        error.InvalidPpuTickProvenance,
        binding.generateMachineExecutionWitness(
            std.testing.allocator,
            serviced,
            &.{service},
            3,
        ),
    );
    try std.testing.expectError(
        error.UnscheduledServicePpuMmio,
        binding.generateFromMachineExecution(
            std.testing.allocator,
            0,
            5,
            .{},
            &.{interruptService(0xff41, false)},
        ),
    );
}

test "PPU machine adapter excludes field wrap and malformed scheduler rows" {
    const instruction_trace = accessStep();
    var instruction = machine.CartridgeStepResult{
        .before = machineState(instruction_trace.instruction.before, 0, 0),
        .after = machineState(instruction_trace.instruction.after, 0, 0),
        .event = .instruction,
        .m_cycles = 1,
        .instruction = instruction_trace,
    };
    var boundary = try binding.generateFromMachineExecution(
        std.testing.allocator,
        M31_MODULUS - 2,
        M31_MODULUS - 1,
        .{},
        &.{instruction},
    );
    defer boundary.deinit(std.testing.allocator);
    try std.testing.expectEqual(M31_MODULUS - 1, boundary.final_mcycle);
    try std.testing.expectError(
        error.InvalidPpuClockBoundary,
        binding.generateFromMachineExecution(
            std.testing.allocator,
            M31_MODULUS - 2,
            M31_MODULUS,
            .{},
            &.{instruction},
        ),
    );
    instruction.m_cycles = 2;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        binding.generateFromMachineExecution(
            std.testing.allocator,
            0,
            2,
            .{},
            &.{instruction},
        ),
    );
}

fn machineState(cpu: runner.Cpu, flags: u8, enable: u8) machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = 0,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = flags,
        .interrupt_enable = enable,
    };
}

fn machineResult(
    event: machine.SchedulerEvent,
    before: machine.MachineState,
    after: machine.MachineState,
    m_cycles: u3,
) machine.CartridgeStepResult {
    return .{
        .before = before,
        .after = after,
        .event = event,
        .m_cycles = m_cycles,
    };
}

fn interruptService(sp: u16, halted: bool) machine.CartridgeStepResult {
    const cpu = runner.Cpu{
        .pc = 0x2345,
        .sp = sp,
        .ime = true,
        .halted = halted,
    };
    var after_cpu = cpu;
    after_cpu.pc = 0x40;
    after_cpu.sp -%= 2;
    after_cpu.ime = false;
    after_cpu.halted = false;
    var result = machineResult(
        .interrupt_service,
        machineState(cpu, 1, 1),
        machineState(after_cpu, 0, 1),
        if (halted) 6 else 5,
    );
    result.interrupt_index = 0;
    const offset: u3 = if (halted) 1 else 0;
    result.service.count = 5 + offset;
    if (halted) result.service.cycles[0].kind = .halt_idle;
    result.service.cycles[offset].kind = .dummy_read;
    result.service.cycles[offset].access =
        serviceAccess(cpu.pc, .read, 0);
    result.service.cycles[offset + 1].kind = .oam_bug;
    result.service.cycles[offset + 2].kind = .no_access;
    result.service.cycles[offset + 3].kind = .stack_high;
    result.service.cycles[offset + 3].access =
        serviceAccess(sp -% 1, .write, 0x23);
    result.service.cycles[offset + 4].kind = .stack_low;
    result.service.cycles[offset + 4].access =
        serviceAccess(sp -% 2, .write, 0x45);
    result.service.ie_resample = .{
        .after_cycle = offset + 3,
        .value = 1,
    };
    result.service.if_resample = .{
        .after_cycle = offset + 4,
        .value = 1,
    };
    result.service.acknowledgement = .{
        .during_cycle = offset + 4,
        .index = 0,
        .before = 1,
        .after = 0,
    };
    return result;
}

fn serviceAccess(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) runner.cartridge_memory.Access {
    const fixed_rom = address <= 0x3fff and action == .read;
    return .{
        .logical_address = address,
        .action = action,
        .region = if (binding.registerForAddress(address) != null)
            .ppu_mmio
        else if (fixed_rom)
            .cartridge_rom
        else
            .system,
        .physical_offset = if (fixed_rom) address else null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}

fn accessStep() runner.CartridgeStepTrace {
    var step = std.mem.zeroes(runner.CartridgeStepTrace);
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = runner.ppu_mmio.LYC_ADDRESS,
        .value = 0x22,
        .action = .write,
    };
    step.accesses[0] = .{
        .logical_address = runner.ppu_mmio.LYC_ADDRESS,
        .action = .write,
        .region = .ppu_mmio,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0x22,
    };
    return step;
}
