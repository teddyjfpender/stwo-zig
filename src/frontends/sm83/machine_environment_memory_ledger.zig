//! Small ordered byte/clock ledger shared by machine and device replay.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const joypad_trace = @import("joypad_trace.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const ppu_mmio = @import("runner/ppu_mmio.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const memory_clock = memory_lookup.memory_clock;

const IF: u17 = runner.cartridge_memory.INTERRUPT_FLAGS;

pub const Predecessor = struct {
    clock: u32,
    value: u8,
};

pub const Ledger = struct {
    bytes: []u8,
    clocks: []u32,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        initial: memory_lookup.Images,
    ) !Ledger {
        const bytes = try allocator.alloc(u8, memory_lookup.KEY_COUNT);
        errdefer allocator.free(bytes);
        @memcpy(
            bytes[0..memory_lookup.SYSTEM_SIZE],
            initial.system.bytes,
        );
        @memcpy(
            bytes[memory_lookup.SYSTEM_SIZE..],
            initial.sram.bytes,
        );
        const clocks = try allocator.alloc(u32, memory_lookup.KEY_COUNT);
        errdefer allocator.free(clocks);
        @memset(clocks, 0);
        return .{
            .bytes = bytes,
            .clocks = clocks,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Ledger) void {
        self.allocator.free(self.clocks);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn predecessor(self: *const Ledger, key: u17) Predecessor {
        return .{
            .clock = self.clocks[key],
            .value = self.bytes[key],
        };
    }

    pub fn read(
        self: *Ledger,
        key: u17,
        expected: u8,
        mcycle: u32,
        phase: u32,
    ) !Predecessor {
        const previous = self.predecessor(key);
        if (previous.value != expected) return error.MemoryReadMismatch;
        try self.advance(key, previous.value, mcycle, phase);
        return previous;
    }

    pub fn write(
        self: *Ledger,
        key: u17,
        next: u8,
        mcycle: u32,
        phase: u32,
    ) !Predecessor {
        const previous = self.predecessor(key);
        try self.advance(key, next, mcycle, phase);
        return previous;
    }

    pub fn advance(
        self: *Ledger,
        key: u17,
        next: u8,
        mcycle: u32,
        phase: u32,
    ) !void {
        if (key >= memory_lookup.KEY_COUNT)
            return error.MemoryKeyOutOfRange;
        const clock = canonicalClock(mcycle, phase) catch
            return error.NonCanonicalMemoryClock;
        _ = try difference(self.clocks[key], clock);
        self.bytes[key] = next;
        self.clocks[key] = clock;
    }

    pub fn writeFinalClocks(
        self: *const Ledger,
        out: []M31,
    ) !void {
        if (out.len != memory_lookup.BOUNDARY_SIZE)
            return error.InvalidFinalClockShape;
        for (self.clocks, 0..) |clock, key| {
            out[
                try @import("stwo_core").air.utils
                    .circleBitReversedIndex(
                    memory_lookup.BOUNDARY_LOG_SIZE,
                    key,
                )
            ] = M31.fromCanonical(clock);
        }
    }
};

pub fn canonicalClock(mcycle: u32, phase: u32) !u32 {
    return memory_clock.phaseClock(mcycle, phase) catch |err| switch (err) {
        error.MemoryClockOverflow => error.MemoryClockOverflow,
        error.MemoryClockOutsideField,
        error.InvalidMemoryClockPhase,
        => error.NonCanonicalMemoryClock,
    };
}

pub fn difference(previous: u32, next: u32) !u32 {
    if (previous >= next) return error.InvalidMemoryClock;
    const result = next - previous - 1;
    if (result >= (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
        return error.MemoryClockDifferenceTooLarge;
    return result;
}

pub const Cursor = struct {
    joypad: usize = 0,
    timer: usize = 0,
    ppu: usize = 0,
    dma: usize = 0,
    observation: usize = 0,
    action: u32 = 0,
    joypad_after: ?runner.joypad.State = null,
    timer_after: ?runner.timer.Timer = null,
    ppu_after: ?ppu_binding.State = null,
    dma_after: ?runner.dma.State = null,
};

pub fn consumeAction(
    cursor: *Cursor,
    mcycle: u32,
    results: []const machine.CartridgeStepResult,
    events: []const joypad_trace.EventRow,
    predecessors: []joypad_if.Predecessor,
    ledger: *Ledger,
) !void {
    if (cursor.joypad >= events.len) return;
    const event = events[cursor.joypad];
    if (event.mcycle != mcycle or event.provenance != .action_index)
        return;
    if (event.provenance.action_index != cursor.action)
        return error.InvalidJoypadActionOrder;
    try consumeJoypadEvent(
        cursor,
        results,
        events,
        predecessors,
        ledger,
        .{ .action_index = cursor.action },
    );
    cursor.action = std.math.add(u32, cursor.action, 1) catch
        return error.TooManyJoypadActions;
    if (cursor.joypad < events.len and
        events[cursor.joypad].mcycle == mcycle and
        events[cursor.joypad].provenance == .action_index)
        return error.JoypadPhaseCollision;
}

pub fn consumeJoypadWrite(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    access: ?runner.cartridge_memory.Access,
    results: []const machine.CartridgeStepResult,
    events: []const joypad_trace.EventRow,
    predecessors: []joypad_if.Predecessor,
    ledger: *Ledger,
) !void {
    const item = access orelse return;
    if (item.region != .joypad_mmio or item.action != .write) return;
    try consumeJoypadEvent(
        cursor,
        results,
        events,
        predecessors,
        ledger,
        .{ .execution_write = .{
            .execution_row = @intCast(row),
            .cycle = @intCast(cycle),
        } },
    );
    if (events[cursor.joypad - 1].mcycle != mcycle)
        return error.InvalidJoypadEventClock;
}

pub fn consumeJoypadTick(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    results: []const machine.CartridgeStepResult,
    events: []const joypad_trace.EventRow,
    predecessors: []joypad_if.Predecessor,
    ledger: *Ledger,
) !void {
    try consumeJoypadEvent(
        cursor,
        results,
        events,
        predecessors,
        ledger,
        .{ .execution_tick = .{
            .execution_row = @intCast(row),
            .cycle = @intCast(cycle),
        } },
    );
    if (events[cursor.joypad - 1].mcycle != mcycle)
        return error.InvalidJoypadEventClock;
}

fn consumeJoypadEvent(
    cursor: *Cursor,
    results: []const machine.CartridgeStepResult,
    events: []const joypad_trace.EventRow,
    predecessors: []joypad_if.Predecessor,
    ledger: *Ledger,
    expected: joypad_trace.Provenance,
) !void {
    if (cursor.joypad >= events.len) return error.MissingJoypadEvent;
    const event = events[cursor.joypad];
    if (!std.meta.eql(event.provenance, expected))
        return error.InvalidJoypadEventProvenance;
    _ = joypad_binding.machineColumns(event, results) catch
        return error.InvalidJoypadEvent;
    if (cursor.joypad_after) |before|
        if (!std.meta.eql(before, event.transition.before))
            return error.DisconnectedJoypadState;
    if (event.transition.interrupt_requested) {
        const previous = ledger.predecessor(IF);
        predecessors[cursor.joypad] = .{
            .clock = previous.clock,
            .value = previous.value,
        };
        const semantic = try joypad_if.accessForEvent(
            event,
            predecessors[cursor.joypad],
        );
        try ledger.advance(
            IF,
            semantic.next_value,
            event.mcycle,
            switch (event.transition.event) {
                .set_pressed => memory_clock.ACTION_PHASE,
                .write_p1 => memory_clock.CPU_PHASE,
                .tick_mcycle => memory_clock.JOYPAD_TICK_PHASE,
            },
        );
    } else {
        _ = try joypad_if.accessForEvent(event, .{});
    }
    cursor.joypad_after = event.transition.after;
    cursor.joypad += 1;
}

pub fn consumeTimerWrite(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    access: ?runner.cartridge_memory.Access,
    results: []const machine.CartridgeStepResult,
    events: []const timer_binding.EventRow,
) !void {
    const item = access orelse return;
    if (item.region != .timer_mmio or item.action != .write) return;
    try consumeTimerEvent(
        cursor,
        mcycle,
        results,
        events,
        .{ .execution_write = .{
            .execution_row = @intCast(row),
            .cycle = @intCast(cycle),
        } },
    );
}

pub fn consumeTimerTick(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    results: []const machine.CartridgeStepResult,
    events: []const timer_binding.EventRow,
    predecessors: []timer_if.Predecessor,
    ledger: *Ledger,
) !void {
    const index = cursor.timer;
    try consumeTimerEvent(
        cursor,
        mcycle,
        results,
        events,
        .{ .execution_tick = .{
            .execution_row = @intCast(row),
            .cycle = @intCast(cycle),
        } },
    );
    const event = events[index];
    if (event.transition.interrupt_requested) {
        const previous = ledger.predecessor(IF);
        predecessors[index] = .{
            .clock = previous.clock,
            .value = previous.value,
        };
        const semantic = try timer_if.accessForEvent(
            event,
            predecessors[index],
        );
        try ledger.advance(
            IF,
            semantic.next_value,
            mcycle,
            memory_clock.TIMER_PHASE,
        );
    } else {
        _ = try timer_if.accessForEvent(event, .{});
    }
}

fn consumeTimerEvent(
    cursor: *Cursor,
    mcycle: u32,
    results: []const machine.CartridgeStepResult,
    events: []const timer_binding.EventRow,
    expected: timer_binding.Provenance,
) !void {
    if (cursor.timer >= events.len) return error.MissingTimerEvent;
    const event = events[cursor.timer];
    if (event.mcycle != mcycle)
        return error.InvalidTimerEventClock;
    if (!std.meta.eql(event.provenance, expected))
        return error.InvalidTimerEventProvenance;
    _ = timer_binding.machineColumns(event, results) catch
        return error.InvalidTimerEvent;
    if (cursor.timer_after) |before|
        if (!std.meta.eql(before, event.transition.before))
            return error.DisconnectedTimerState;
    cursor.timer_after = event.transition.after;
    cursor.timer += 1;
}

pub fn consumePpuWrite(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    access: ?runner.cartridge_memory.Access,
    events: []const ppu_binding.EventRow,
) !void {
    const item = access orelse return;
    if (item.region != .ppu_mmio or item.action != .write or
        item.logical_address == ppu_mmio.LY_ADDRESS)
        return;
    const register = ppu_binding.registerForAddress(
        item.logical_address,
    ) orelse return error.InvalidPpuMmioMetadata;
    if (ppu_binding.latchIndex(register) != null) return;
    const index = cursor.ppu;
    try consumePpuEvent(
        cursor,
        mcycle,
        events,
        .{ .execution_write = .{
            .execution_row = @intCast(row),
            .cycle = @intCast(cycle),
        } },
        null,
        null,
        null,
    );
    const event = events[index];
    const expected: runner.ppu_timing.Event = switch (register) {
        .lcdc => .{ .write_lcdc = item.value },
        .stat => .{ .write_stat = item.value },
        .lyc => .{ .write_lyc = item.value },
        .ly, .scy, .scx, .wy => unreachable,
    };
    if (!std.meta.eql(event.transition.event, expected))
        return error.InvalidPpuWriteProvenance;
}

pub fn consumePpuTicks(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    access: ?runner.cartridge_memory.Access,
    events: []const ppu_binding.EventRow,
    predecessors: []ppu_if.Predecessor,
    ledger: *Ledger,
) !void {
    var expected_read: ?ppu_binding.Register = null;
    var expected_ly_write: ?u8 = null;
    var expected_latch_write: ?ppu_binding.RegisterAccess = null;
    if (access) |item| {
        if (item.region == .ppu_mmio) {
            const register = ppu_binding.registerForAddress(
                item.logical_address,
            ) orelse return error.InvalidPpuMmioMetadata;
            if (item.action == .read) expected_read = register;
            if (item.action == .write and register == .ly)
                expected_ly_write = item.value;
            if (item.action == .write and
                ppu_binding.latchIndex(register) != null)
            {
                expected_latch_write = .{
                    .register = register,
                    .value = item.value,
                };
            }
        }
    }
    if (access) |item| {
        if (item.region == .ppu_mmio and item.action == .write and
            item.logical_address != ppu_mmio.LY_ADDRESS)
        {
            if (cursor.ppu == 0) return error.MissingPpuWriteEvent;
            const write_index = cursor.ppu - 1;
            try applyPpuIf(
                events[write_index],
                write_index,
                predecessors,
                ledger,
            );
        }
    }
    for (0..4) |phase| {
        const index = cursor.ppu;
        try consumePpuEvent(
            cursor,
            mcycle,
            events,
            .{ .execution_tick = .{
                .position = .{
                    .execution_row = @intCast(row),
                    .cycle = @intCast(cycle),
                },
                .phase = @intCast(phase),
            } },
            if (phase == 0) expected_read else null,
            if (phase == 0) expected_ly_write else null,
            if (phase == 0) expected_latch_write else null,
        );
        try applyPpuIf(
            events[index],
            index,
            predecessors,
            ledger,
        );
    }
}

fn consumePpuEvent(
    cursor: *Cursor,
    mcycle: u32,
    events: []const ppu_binding.EventRow,
    expected: ppu_binding.Provenance,
    expected_read: ?ppu_binding.Register,
    expected_ly_write: ?u8,
    expected_latch_write: ?ppu_binding.RegisterAccess,
) !void {
    if (cursor.ppu >= events.len) return error.MissingPpuEvent;
    const event = events[cursor.ppu];
    if (event.mcycle != mcycle)
        return error.InvalidPpuEventClock;
    if (!std.meta.eql(event.provenance, expected) or
        event.read_register != expected_read or
        event.ignored_ly_write != expected_ly_write or
        !std.meta.eql(event.latch_write, expected_latch_write))
        return error.InvalidPpuEventProvenance;
    _ = ppu_binding.columns(event) catch
        return error.InvalidPpuEvent;
    const before = ppu_binding.State{
        .timing = event.transition.before,
        .lcdc = event.lcdc_before,
        .scy = event.latches_before[0],
        .scx = event.latches_before[1],
        .wy = event.latches_before[2],
    };
    const after = ppu_binding.State{
        .timing = event.transition.after,
        .lcdc = event.lcdc_after,
        .scy = event.latches_after[0],
        .scx = event.latches_after[1],
        .wy = event.latches_after[2],
    };
    if (cursor.ppu_after) |previous|
        if (!std.meta.eql(previous, before))
            return error.DisconnectedPpuState;
    cursor.ppu_after = after;
    cursor.ppu += 1;
}

fn applyPpuIf(
    event: ppu_binding.EventRow,
    index: usize,
    predecessors: []ppu_if.Predecessor,
    ledger: *Ledger,
) !void {
    const requested = event.transition.interrupts.vblank or
        event.transition.interrupts.stat;
    if (!requested) {
        _ = try ppu_if.accessForEvent(event, .{});
        return;
    }
    const previous = ledger.predecessor(IF);
    predecessors[index] = .{
        .clock = previous.clock,
        .value = previous.value,
    };
    const semantic = try ppu_if.accessForEvent(
        event,
        predecessors[index],
    );
    try ledger.advance(
        IF,
        semantic.next_value,
        event.mcycle,
        memory_clock.PPU_PHASE,
    );
}

pub fn consumeDma(
    cursor: *Cursor,
    mcycle: u32,
    row: usize,
    cycle: usize,
    results: []const machine.CartridgeStepResult,
    events: []const dma_binding.EventRow,
    predecessors: []dma_memory.Predecessors,
    ledger: *Ledger,
) !void {
    if (cursor.dma >= events.len) return error.MissingDmaEvent;
    const index = cursor.dma;
    const event = events[index];
    if (event.mcycle != mcycle or
        event.provenance.execution_row != row or
        event.provenance.cycle != cycle)
        return error.InvalidDmaEventProvenance;
    _ = dma_binding.machineColumns(event, results) catch
        return error.InvalidDmaEvent;
    if (cursor.dma_after) |before|
        if (!std.meta.eql(before, event.transition.before))
            return error.DisconnectedDmaState;
    if (event.transition.before.clock != mcycle)
        return error.InvalidDmaEventClock;
    if (event.transition.transfer) |transfer| {
        if (transfer.source_address == transfer.destination_address)
            return error.DmaMemoryPhaseCollision;
        const source = ledger.predecessor(
            @intCast(transfer.source_address),
        );
        const destination = ledger.predecessor(
            @intCast(transfer.destination_address),
        );
        predecessors[index] = .{
            .source = .{
                .clock = source.clock,
                .value = source.value,
            },
            .destination = .{
                .clock = destination.clock,
                .value = destination.value,
            },
        };
        const semantic = try dma_memory.accessesForEvent(
            event,
            predecessors[index],
        );
        if (!semantic.source.enabled or !semantic.destination.enabled)
            return error.MissingDmaMemoryAccess;
        _ = try ledger.read(
            semantic.source.address,
            semantic.source.previous_value,
            mcycle,
            memory_clock.DMA_PHASE,
        );
        _ = try ledger.write(
            semantic.destination.address,
            semantic.destination.next_value,
            mcycle,
            memory_clock.DMA_PHASE,
        );
    } else {
        _ = try dma_memory.accessesForEvent(event, .{});
    }
    cursor.dma_after = event.transition.after;
    cursor.dma += 1;
}

pub fn consumeObservations(
    cursor: *Cursor,
    mcycle: u32,
    samples: []const observation.Sample,
    predecessors: []observation.Predecessor,
    ledger: *Ledger,
) !void {
    while (cursor.observation < samples.len and
        samples[cursor.observation].mcycle == mcycle)
    {
        const index = cursor.observation;
        const sample = samples[index];
        const previous = ledger.predecessor(sample.key);
        if (previous.value != sample.expected)
            return error.ObservationValueMismatch;
        predecessors[index] = .{ .clock = previous.clock };
        _ = try observation.accessForSample(
            sample,
            predecessors[index],
        );
        _ = try ledger.read(
            sample.key,
            sample.expected,
            mcycle,
            memory_clock.OBSERVATION_PHASE,
        );
        cursor.observation += 1;
    }
}
