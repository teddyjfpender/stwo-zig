//! Minimal interrupt/timer scheduler around the instruction runner.
const std = @import("std");
const runner = @import("mod.zig");
const timer = @import("timer.zig");
const live_dma = @import("live_dma.zig");
const mbc3 = @import("../cartridge/mbc3.zig");
const interrupt_service = @import("interrupt_service.zig");
const DIV: u16 = 0xff04;
const TIMA: u16 = 0xff05;
const TMA: u16 = 0xff06;
const TAC: u16 = 0xff07;
const IF: u16 = 0xff0f;
const IE: u16 = 0xffff;
const TIMER_INTERRUPT = timer.TIMER_INTERRUPT;
pub const SchedulerEvent = enum {
    instruction,
    halt_idle,
    halt_wake,
    interrupt_service,
};
pub const MachineState = struct {
    cpu: runner.Cpu,
    halt_bug: bool,
    div_counter: u16,
    tima: u8,
    tma: u8,
    tac: u8,
    timer_reload: timer.ReloadState,
    interrupt_flags: u8,
    interrupt_enable: u8,
};
pub const StepResult = struct {
    before: MachineState,
    after: MachineState,
    event: SchedulerEvent,
    m_cycles: u3,
    instruction: ?runner.StepTrace = null,
    interrupt_index: ?u3 = null,
    pub fn hasCanonicalShape(self: StepResult) bool {
        return switch (self.event) {
            .instruction => if (self.instruction) |trace|
                self.interrupt_index == null and
                    self.m_cycles == trace.cycle_count and
                    self.hasCanonicalInstructionBefore(trace.before) and
                    std.meta.eql(self.after.cpu, trace.after)
            else
                false,
            .halt_idle => self.instruction == null and
                self.interrupt_index == null and
                self.m_cycles == 1 and
                !self.before.halt_bug and
                !self.after.halt_bug and
                self.hasCanonicalHaltTransition(false),
            .halt_wake => self.instruction == null and
                self.interrupt_index == null and
                self.m_cycles == 1 and
                !self.before.halt_bug and
                !self.after.halt_bug and
                self.hasCanonicalHaltTransition(true),
            .interrupt_service => if (self.interrupt_index) |index|
                self.instruction == null and
                    self.m_cycles ==
                        @as(u3, if (self.before.cpu.halted) 6 else 5) and
                    self.before.cpu.ime and
                    !self.before.cpu.stopped and
                    self.before.interrupt_enable &
                        self.before.interrupt_flags & 0x1f != 0 and
                    !self.before.halt_bug and
                    !self.after.halt_bug and
                    !self.after.cpu.ime and
                    !self.after.cpu.ime_enable_pending and
                    !self.after.cpu.halted and
                    self.after.cpu.sp == self.before.cpu.sp -% 2 and
                    self.after.cpu.pc == 0x40 + @as(u16, index) * 8
            else
                self.instruction == null and
                    self.m_cycles ==
                        @as(u3, if (self.before.cpu.halted) 6 else 5) and
                    self.before.cpu.ime and
                    !self.before.cpu.stopped and
                    self.before.interrupt_enable &
                        self.before.interrupt_flags & 0x1f != 0 and
                    !self.before.halt_bug and
                    !self.after.halt_bug and
                    !self.after.cpu.ime and
                    !self.after.cpu.ime_enable_pending and
                    !self.after.cpu.halted and
                    self.after.cpu.sp == self.before.cpu.sp -% 2 and
                    self.after.cpu.pc == 0,
        };
    }
    fn hasCanonicalInstructionBefore(self: StepResult, actual: runner.Cpu) bool {
        if (self.before.cpu.halted) return false;
        return std.meta.eql(self.before.cpu, actual);
    }
    fn hasCanonicalHaltTransition(self: StepResult, wake: bool) bool {
        if (!self.before.cpu.halted) return false;
        var expected = self.before.cpu;
        if (expected.ime_enable_pending) {
            expected.ime = true;
            expected.ime_enable_pending = false;
        }
        expected.halted = !wake;
        return std.meta.eql(expected, self.after.cpu);
    }
};
pub const CartridgeServiceTrace = interrupt_service.Trace;
pub const CartridgeServiceCycle = interrupt_service.ServiceCycle;
pub const CartridgeServiceCycleKind = interrupt_service.CycleKind;
pub const CartridgeServiceLogicalSample = interrupt_service.LogicalSample;
pub const CartridgeServiceAcknowledgement = interrupt_service.Acknowledgement;
/// Scheduler result that retains the cartridge metadata discarded by the flat
/// machine. Instruction rows carry the complete `CartridgeStepTrace`; service
/// rows carry their ordered non-instruction memory operations separately.
pub const CartridgeStepResult = struct {
    before: MachineState,
    after: MachineState,
    event: SchedulerEvent,
    m_cycles: u3,
    instruction: ?runner.CartridgeStepTrace = null,
    interrupt_index: ?u3 = null,
    service: CartridgeServiceTrace = .{},
    mapper_before: mbc3.State = .{},
    mapper_after: mbc3.State = .{},

    pub fn schedulerResult(self: CartridgeStepResult) StepResult {
        return .{
            .before = self.before,
            .after = self.after,
            .event = self.event,
            .m_cycles = self.m_cycles,
            .instruction = if (self.instruction) |trace|
                trace.instruction
            else
                null,
            .interrupt_index = self.interrupt_index,
        };
    }

    pub fn hasCanonicalShape(self: CartridgeStepResult) bool {
        const result = self.schedulerResult();
        if (!result.hasCanonicalShape()) return false;
        return switch (self.event) {
            .instruction => self.instruction != null and
                self.service.isEmpty() and
                cartridgeInstructionIsCanonical(
                    self.instruction.?,
                    self.mapper_before,
                    self.mapper_after,
                ),
            .halt_idle, .halt_wake => self.instruction == null and
                self.service.isEmpty() and
                std.meta.eql(self.mapper_before, self.mapper_after),
            .interrupt_service => self.instruction == null and
                self.service.hasCanonicalShape(
                    .{
                        .halted = self.before.cpu.halted,
                        .return_pc = self.before.cpu.pc,
                        .stack_pointer = self.before.cpu.sp,
                        .interrupt_enable_before = self.before.interrupt_enable,
                        .interrupt_enable_after = self.after.interrupt_enable,
                        .interrupt_flags_after = self.after.interrupt_flags,
                        .interrupt_index = self.interrupt_index,
                        .mapper_before = self.mapper_before,
                        .mapper_after = self.mapper_after,
                    },
                ),
        };
    }
};
pub const StepError = runner.StepError || error{Stopped};
pub const CartridgeStepError =
    runner.CartridgeStepError ||
    error{ Stopped, DmaAlreadyAttached, UnsupportedActiveDmaHalt };
pub const Machine = struct {
    cpu: runner.Cpu,
    memory: *runner.Memory,
    timer: timer.Timer,
    halt_bug: bool = false,
    pub fn init(memory: *runner.Memory, cpu: runner.Cpu) Machine {
        memory.write(DIV, 0);
        return restore(
            memory,
            cpu,
            .{
                .tima = memory.read(TIMA),
                .tma = memory.read(TMA),
                .tac = @truncate(memory.read(TAC)),
            },
            false,
        ) catch unreachable;
    }
    /// Restores a complete scheduler checkpoint without applying boot-time
    /// divider initialization. Attached PPU state remains owned by `memory`.
    pub fn restore(
        memory: *runner.Memory,
        cpu: runner.Cpu,
        restored_timer: timer.Timer,
        halt_bug: bool,
    ) error{TimerAlreadyAttached}!Machine {
        if (memory.timer != null) return error.TimerAlreadyAttached;
        var restored = Machine{
            .cpu = cpu,
            .memory = memory,
            .timer = restored_timer,
            .halt_bug = halt_bug,
        };
        restored.memory.attachTimer(&restored.timer);
        restored.memory.detachTimer();
        return restored;
    }
    pub fn step(self: *Machine) StepError!StepResult {
        return schedulerStep(self);
    }
};
pub const CartridgeMachine = struct {
    cpu: runner.Cpu,
    memory: *runner.cartridge_memory.Memory,
    timer: timer.Timer,
    dma: live_dma.Controller,
    halt_bug: bool = false,
    pub fn init(
        memory: *runner.cartridge_memory.Memory,
        cpu: runner.Cpu,
    ) error{ TimerAlreadyAttached, DmaAlreadyAttached }!CartridgeMachine {
        if (memory.timer != null) return error.TimerAlreadyAttached;
        if (memory.dma != null) return error.DmaAlreadyAttached;
        memory.system[DIV] = 0;
        return restore(
            memory,
            cpu,
            .{
                .tima = memory.system[TIMA],
                .tma = memory.system[TMA],
                .tac = @truncate(memory.system[TAC]),
            },
            false,
        );
    }
    /// Restores a complete scheduler checkpoint without applying boot-time
    /// divider initialization. Attached PPU/joypad state remains owned by
    /// `memory`; IF synchronization is therefore preserved.
    pub fn restore(
        memory: *runner.cartridge_memory.Memory,
        cpu: runner.Cpu,
        restored_timer: timer.Timer,
        halt_bug: bool,
    ) error{ TimerAlreadyAttached, DmaAlreadyAttached }!CartridgeMachine {
        if (memory.timer != null) return error.TimerAlreadyAttached;
        if (memory.dma != null) return error.DmaAlreadyAttached;
        var restored = CartridgeMachine{
            .cpu = cpu,
            .memory = memory,
            .timer = restored_timer,
            .dma = live_dma.Controller.init(.{
                .page = memory.system[runner.dma.DMA_ADDRESS],
            }) catch unreachable,
            .halt_bug = halt_bug,
        };
        restored.memory.attachTimer(&restored.timer);
        restored.memory.detachTimer();
        return restored;
    }
    pub fn step(
        self: *CartridgeMachine,
    ) CartridgeStepError!CartridgeStepResult {
        if (self.cpu.halted and self.dma.state.isActive())
            return error.UnsupportedActiveDmaHalt;
        if (self.memory.dma != null) return error.DmaAlreadyAttached;
        self.memory.attachDma(&self.dma) catch unreachable;
        defer self.memory.detachDma();
        const mapper_before = self.memory.mapper;
        var result = try schedulerStep(self);
        result.mapper_before = mapper_before;
        result.mapper_after = self.memory.mapper;
        return result;
    }
};
fn SchedulerResult(comptime T: type) type {
    return if (T == Machine) StepResult else CartridgeStepResult;
}
fn SchedulerStepError(comptime T: type) type {
    return if (T == Machine) StepError else CartridgeStepError;
}

fn InstructionTrace(comptime T: type) type {
    return if (T == Machine) runner.StepTrace else runner.CartridgeStepTrace;
}

/// One transition path owns event selection for both address spaces. Memory
/// adapters below differ only where cartridge metadata must be retained.
fn schedulerStep(
    self: anytype,
) SchedulerStepError(@TypeOf(self.*))!SchedulerResult(@TypeOf(self.*)) {
    const T = @TypeOf(self.*);
    if (self.cpu.stopped) return error.Stopped;
    const before = machineState(self);

    if (self.cpu.halted) {
        const effective_ime = self.cpu.ime;
        const queue_before_tick = interruptQueue(self);
        tickMcycles(self, 1);
        // SameBoy samples the interrupt queue halfway through the halted
        // M-cycle. Device ticks are atomic here, so resample immediately
        // afterwards instead of using the stale pre-tick queue.
        const queue = interruptQueue(self);
        if (self.cpu.ime_enable_pending) {
            self.cpu.ime = true;
            self.cpu.ime_enable_pending = false;
        }
        if (queue == 0)
            return eventResult(T, before, machineState(self), .halt_idle, 1);
        self.cpu.halted = false;
        if (!effective_ime)
            return eventResult(T, before, machineState(self), .halt_wake, 1);
        // The canonical service row requires a request in its public before
        // state. Split an in-cycle request into a one-cycle wake followed by
        // the ordinary five-cycle service on the next scheduler step.
        if (queue_before_tick == 0)
            return eventResult(T, before, machineState(self), .halt_wake, 1);
        var service = CartridgeServiceTrace{};
        service.append(.halt_idle, null);
        const index = try serviceInterrupt(self, queue, &service);
        return serviceResult(
            T,
            before,
            machineState(self),
            6,
            index,
            service,
        );
    }

    const queue = interruptQueue(self);
    if (queue != 0 and self.cpu.ime) {
        var service = CartridgeServiceTrace{};
        const index = try serviceInterrupt(self, queue, &service);
        return serviceResult(
            T,
            before,
            machineState(self),
            5,
            index,
            service,
        );
    }

    var instruction = try runInstruction(self);
    if (instructionOperation(instruction) == .halt and
        interruptQueue(self) != 0)
    {
        self.cpu.halted = false;
        if (self.cpu.ime) {
            self.cpu.pc -%= 1;
        } else {
            self.halt_bug = true;
        }
        setInstructionAfter(&instruction, self.cpu);
    }
    return instructionResult(
        T,
        before,
        machineState(self),
        instruction,
    );
}

fn machineState(self: anytype) MachineState {
    return .{
        .cpu = self.cpu,
        .halt_bug = self.halt_bug,
        .div_counter = self.timer.div_counter,
        .tima = self.timer.readTima(),
        .tma = self.timer.tma,
        .tac = self.timer.tac,
        .timer_reload = self.timer.reload_state,
        .interrupt_flags = rawRead(self, IF),
        .interrupt_enable = rawRead(self, IE),
    };
}

fn interruptQueue(self: anytype) u8 {
    return rawRead(self, IE) & rawRead(self, IF) & 0x1f;
}

fn serviceInterrupt(
    self: anytype,
    initial_queue: u8,
    service: *CartridgeServiceTrace,
) SchedulerStepError(@TypeOf(self.*))!?u3 {
    std.debug.assert(initial_queue != 0);
    const return_pc = self.cpu.pc;
    self.cpu.ime = false;
    self.cpu.ime_enable_pending = false;
    self.halt_bug = false;

    _ = try trackedRead(self, service, .dummy_read, return_pc);
    tickMcycles(self, 1);
    service.append(.oam_bug, null);
    tickMcycles(self, 1);
    service.append(.no_access, null);
    tickMcycles(self, 1);

    self.cpu.sp -%= 1;
    try trackedWrite(
        self,
        service,
        .stack_high,
        self.cpu.sp,
        @truncate(return_pc >> 8),
    );
    service.ie_resample = .{
        .after_cycle = service.count - 1,
        .value = rawRead(self, IE),
    };
    tickMcycles(self, 1);

    self.cpu.sp -%= 1;
    const interrupt_flags_before_low = rawRead(self, IF);
    try trackedWrite(
        self,
        service,
        .stack_low,
        self.cpu.sp,
        @truncate(return_pc),
    );
    service.if_resample = .{
        .after_cycle = service.count - 1,
        .value = if (self.cpu.sp == IF)
            interrupt_flags_before_low & 0x1f
        else
            rawRead(self, IF) & 0x1f,
    };

    const queue = service.ie_resample.?.value &
        service.if_resample.?.value & 0x1f;
    const index: ?u3 = if (queue == 0) null else @intCast(@ctz(queue));
    if (index) |selected| {
        const interrupt_flags_before = rawRead(self, IF);
        const interrupt_flags_after =
            interrupt_flags_before & ~(@as(u8, 1) << selected);
        rawWrite(self, IF, interrupt_flags_after);
        service.acknowledgement = .{
            .during_cycle = service.count - 1,
            .index = selected,
            .before = interrupt_flags_before,
            .after = interrupt_flags_after,
        };
        self.cpu.pc = 0x40 + @as(u16, selected) * 8;
    } else {
        self.cpu.pc = 0;
    }
    tickMcycles(self, 1);
    return index;
}

fn runInstruction(
    self: anytype,
) SchedulerStepError(@TypeOf(self.*))!InstructionTrace(@TypeOf(self.*)) {
    const T = @TypeOf(self.*);
    self.memory.attachTimer(&self.timer);
    defer self.memory.detachTimer();
    if (T == Machine) {
        if (self.halt_bug) {
            self.halt_bug = false;
            return runner.stepWithHaltBug(&self.cpu, self.memory);
        }
        return runner.step(&self.cpu, self.memory);
    }
    if (self.halt_bug) {
        self.halt_bug = false;
        return runner.stepCartridgeWithHaltBug(&self.cpu, self.memory);
    }
    return runner.stepCartridge(&self.cpu, self.memory);
}

fn tickMcycles(self: anytype, count: usize) void {
    const T = @TypeOf(self.*);
    if (T == Machine) {
        self.memory.attachTimer(&self.timer);
        defer self.memory.detachTimer();
        for (0..count) |_| self.memory.tickMcycle();
        return;
    }
    self.memory.attachTimer(&self.timer);
    defer self.memory.detachTimer();
    for (0..count) |_| self.memory.tickMcycle();
}

fn rawRead(self: anytype, address: u16) u8 {
    return if (@TypeOf(self.*) == Machine)
        self.memory.read(address)
    else
        self.memory.system[address];
}

fn rawWrite(self: anytype, address: u16, value: u8) void {
    if (@TypeOf(self.*) == Machine) {
        self.memory.write(address, value);
        return;
    }
    self.memory.system[address] = value;
    if (address == IF) {
        if (self.memory.ppu) |ppu| ppu.interrupt_flags = value;
    }
}

fn trackedRead(
    self: anytype,
    service: *CartridgeServiceTrace,
    kind: interrupt_service.CycleKind,
    address: u16,
) SchedulerStepError(@TypeOf(self.*))!u8 {
    self.memory.attachTimer(&self.timer);
    defer self.memory.detachTimer();
    if (@TypeOf(self.*) == Machine) return self.memory.read(address);
    const result = try self.memory.read(address);
    service.append(kind, result.access);
    return result.value;
}

fn trackedWrite(
    self: anytype,
    service: *CartridgeServiceTrace,
    kind: interrupt_service.CycleKind,
    address: u16,
    value: u8,
) SchedulerStepError(@TypeOf(self.*))!void {
    self.memory.attachTimer(&self.timer);
    defer self.memory.detachTimer();
    if (@TypeOf(self.*) == Machine) {
        self.memory.write(address, value);
        return;
    }
    service.append(kind, try self.memory.write(address, value));
}

fn instructionOperation(instruction: anytype) @TypeOf(
    instructionTrace(instruction).decoded.instruction.operation,
) {
    return instructionTrace(instruction).decoded.instruction.operation;
}

fn instructionTrace(instruction: anytype) runner.StepTrace {
    return if (@TypeOf(instruction) == runner.StepTrace)
        instruction
    else
        instruction.instruction;
}

fn setInstructionAfter(instruction: anytype, cpu: runner.Cpu) void {
    if (@TypeOf(instruction.*) == runner.StepTrace)
        instruction.after = cpu
    else
        instruction.instruction.after = cpu;
}

fn eventResult(
    comptime T: type,
    before: MachineState,
    after: MachineState,
    event: SchedulerEvent,
    m_cycles: u3,
) SchedulerResult(T) {
    if (T == Machine) return .{
        .before = before,
        .after = after,
        .event = event,
        .m_cycles = m_cycles,
    };
    return .{
        .before = before,
        .after = after,
        .event = event,
        .m_cycles = m_cycles,
    };
}

fn serviceResult(
    comptime T: type,
    before: MachineState,
    after: MachineState,
    m_cycles: u3,
    interrupt_index: ?u3,
    service: CartridgeServiceTrace,
) SchedulerResult(T) {
    if (T == Machine) return .{
        .before = before,
        .after = after,
        .event = .interrupt_service,
        .m_cycles = m_cycles,
        .interrupt_index = interrupt_index,
    };
    return .{
        .before = before,
        .after = after,
        .event = .interrupt_service,
        .m_cycles = m_cycles,
        .interrupt_index = interrupt_index,
        .service = service,
    };
}

fn instructionResult(
    comptime T: type,
    before: MachineState,
    after: MachineState,
    instruction: InstructionTrace(T),
) SchedulerResult(T) {
    if (T == Machine) return .{
        .before = before,
        .after = after,
        .event = .instruction,
        .m_cycles = instruction.cycle_count,
        .instruction = instruction,
    };
    return .{
        .before = before,
        .after = after,
        .event = .instruction,
        .m_cycles = instruction.instruction.cycle_count,
        .instruction = instruction,
    };
}

fn cartridgeInstructionIsCanonical(
    trace: runner.CartridgeStepTrace,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
) bool {
    var previous_mapper: ?mbc3.State = null;
    for (trace.instruction.activeCycles(), trace.activeAccesses()) |
        cycle,
        maybe_access,
    | {
        if (cycle.action == .idle) {
            if (maybe_access != null) return false;
            continue;
        }
        const access = maybe_access orelse return false;
        const action: runner.cartridge_memory.Action = switch (cycle.action) {
            .read => .read,
            .write => .write,
            .idle => unreachable,
        };
        if (!matchesAccess(access, cycle.address, action, cycle.value) or
            !canonicalMapperTransition(access))
            return false;
        if (previous_mapper) |previous|
            if (!std.meta.eql(previous, access.mapper_before)) return false;
        if (previous_mapper == null and
            !std.meta.eql(mapper_before, access.mapper_before)) return false;
        previous_mapper = access.mapper_after;
    }
    for (trace.accesses[trace.instruction.cycle_count..]) |access|
        if (access != null) return false;
    return previous_mapper != null and
        std.meta.eql(previous_mapper.?, mapper_after);
}

fn matchesAccess(
    access: runner.cartridge_memory.Access,
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
) bool {
    return access.logical_address == address and
        access.action == action and access.value == value;
}

fn systemAccess(access: runner.cartridge_memory.Access) bool {
    return access.region == .system and access.physical_offset == null and
        std.meta.eql(access.mapper_before, access.mapper_after);
}

fn canonicalMapperTransition(
    access: runner.cartridge_memory.Access,
) bool {
    if (access.action == .write and access.logical_address <= 0x7fff) {
        const expected = mbc3.transition(
            access.mapper_before,
            access.logical_address,
            access.value,
        ) catch return false;
        return access.region == .mapper_control and
            access.physical_offset == null and
            std.meta.eql(access.mapper_after, expected);
    }
    return std.meta.eql(access.mapper_before, access.mapper_after);
}

test "EI delays service one instruction and DI cancels it" {
    try machineTestCases().eiDelay(runner, Machine, SchedulerEvent, IE, IF);
}

test "HALT wakes with IME clear and retains the request" {
    try machineTestCases().haltWake(
        runner,
        Machine,
        SchedulerEvent,
        IE,
        IF,
        TIMER_INTERRUPT,
    );
}

test "HALT idle promotes pending IME and halted service takes six M-cycles" {
    try machineTestCases().haltedService(
        runner,
        Machine,
        SchedulerEvent,
        IE,
        IF,
    );
}

test "HALT bug duplicates the next opcode byte" {
    try machineTestCases().haltBug(runner, Machine, SchedulerEvent, IE, IF);
}

test "interrupt stack write can cancel or reprioritize dispatch through IE" {
    try machineTestCases().interruptAlias(runner, Machine, IE, IF);
}

fn machineTestCases() type {
    return @import("machine_test_cases.zig");
}
