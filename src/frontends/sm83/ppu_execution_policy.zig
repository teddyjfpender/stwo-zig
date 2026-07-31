//! Canonical prover admission for the reduced, non-rendering DMG PPU model.
//!
//! Mode 3 lasts 172...289 dots when scrolling, the window, or objects stall
//! the pixel FIFO. The verifier proves the fixed 172-dot model and binds every
//! CPU VRAM/OAM access to a hardware-certain PPU clock row. STAT accesses are
//! already joined to that row by the PPU-MMIO relation and are constrained by
//! the same policy here. Verifier AIR independently disables HBlank STAT,
//! permits at most one PPU IF request per M-cycle, and rejects every
//! VRAM-source DMA. Pixel output is never a public observation.

const std = @import("std");
const core = @import("stwo_core");
const core_air_utils = core.air.utils;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const dma_binding = @import("air/dma_binding.zig");
const dma_binding_component = @import("air/dma_binding_component.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_binding_component = @import("air/ppu_binding_component.zig");
const machine_access = @import("air/cartridge_machine_access.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const policy_air = @import("ppu_execution_policy_air.zig");

const VRAM_START: u16 = 0x8000;
const VRAM_END: u16 = 0x9fff;
const OAM_START: u16 = 0xfe00;
const OAM_END: u16 = 0xfe9f;
pub const CERTAIN_HBLANK_DOT = policy_air.CERTAIN_HBLANK_DOT;
pub const N_MAIN_COLUMNS = policy_air.N_MAIN_COLUMNS;
pub const N_DMA_INTERACTION_COLUMNS =
    policy_air.N_DMA_INTERACTION_COLUMNS;
pub const N_PPU_INTERACTION_COLUMNS =
    policy_air.N_PPU_INTERACTION_COLUMNS;
pub const N_DMA_CONSTRAINTS = policy_air.N_DMA_CONSTRAINTS;
pub const N_PPU_CONSTRAINTS = policy_air.N_PPU_CONSTRAINTS;
pub const N_MAX_CONSTRAINTS = policy_air.N_MAX_CONSTRAINTS;
pub const MAX_CONSTRAINT_DEGREE = policy_air.MAX_CONSTRAINT_DEGREE;
pub const Claims = policy_air.Claims;
pub const Kind = policy_air.Kind;
pub const evaluatePpuRows = policy_air.evaluatePpuRows;
pub const verifyCancellation = policy_air.verifyCancellation;
pub const Component =
    @import("ppu_execution_policy_component.zig").Component;

pub const Error = error{
    UnsupportedHblankStatInterrupt,
    UnsupportedVariableMode3Access,
    UnsupportedMultiplePpuIfRequests,
    UnsupportedVramDmaPpuConflict,
    InvalidPpuPolicyTrace,
};

/// Two verifier-owned selectors on phase-zero PPU ticks. Their LogUp image is
/// the already execution-bound DMA bus row at the same M-cycle. The selectors
/// are therefore not trusted prover annotations.
pub const Witness = struct {
    log_size: u32,
    event_count: usize,
    main: [N_MAIN_COLUMNS][]M31,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Witness) void {
        self.owned = false;
    }

    pub fn deinit(self: *Witness) void {
        if (self.owned)
            for (self.main) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub const Interaction = struct {
    dma_columns: [N_DMA_INTERACTION_COLUMNS][]M31,
    ppu_columns: [N_PPU_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.dma_columns) |column| self.allocator.free(column);
        for (self.ppu_columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateWitness(
    allocator: std.mem.Allocator,
    log_size: u32,
    events: []const ppu_binding.EventRow,
    results: []const machine.CartridgeStepResult,
) !Witness {
    const size = try traceSize(log_size);
    if (events.len == 0 or events.len > size)
        return error.InvalidPpuPolicyTrace;
    var out = Witness{
        .log_size = log_size,
        .event_count = events.len,
        .main = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (out.main[0..initialized]) |column|
        allocator.free(column);
    for (&out.main) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    for (events, 0..) |event, row| {
        _ = try ppu_binding.columns(event);
        const tick = switch (event.provenance) {
            .execution_tick => |value| value,
            .execution_write, .detached => continue,
        };
        if (tick.phase != 0) continue;
        if (tick.position.execution_row >= results.len)
            return error.InvalidPpuPolicyTrace;
        const validated = machine_access.ValidatedStep.init(
            results[tick.position.execution_row],
        ) catch return error.InvalidPpuPolicyTrace;
        if (tick.position.cycle >= validated.count)
            return error.InvalidPpuPolicyTrace;
        const access = validated.cycles[tick.position.cycle].access orelse
            continue;
        const class = accessClass(access.logical_address) orelse continue;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        out.main[@intFromEnum(class)][storage] = M31.one();
    }
    return out;
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    results: []const machine.CartridgeStepResult,
    dma_log_size: u32,
    dma_events: []const dma_binding.EventRow,
    ppu_log_size: u32,
    ppu_events: []const ppu_binding.EventRow,
    witness: *const Witness,
    relations: dma_execution.Relations,
) !Interaction {
    const dma_size = try traceSize(dma_log_size);
    const ppu_size = try traceSize(ppu_log_size);
    if (dma_events.len == 0 or dma_events.len > dma_size or
        ppu_events.len == 0 or ppu_events.len > ppu_size or
        witness.log_size != ppu_log_size or
        witness.event_count != ppu_events.len)
        return error.InvalidPpuPolicyTrace;
    for (witness.main) |column|
        if (column.len != ppu_size)
            return error.InvalidPpuPolicyTrace;

    var out = Interaction{
        .dma_columns = undefined,
        .ppu_columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var dma_initialized: usize = 0;
    var ppu_initialized: usize = 0;
    errdefer {
        for (out.dma_columns[0..dma_initialized]) |column|
            allocator.free(column);
        for (out.ppu_columns[0..ppu_initialized]) |column|
            allocator.free(column);
    }
    for (&out.dma_columns) |*column| {
        column.* = try allocator.alloc(M31, dma_size);
        @memset(column.*, M31.zero());
        dma_initialized += 1;
    }
    for (&out.ppu_columns) |*column| {
        column.* = try allocator.alloc(M31, ppu_size);
        @memset(column.*, M31.zero());
        ppu_initialized += 1;
    }

    var dma_claim = QM31.zero();
    for (0..dma_size) |row| {
        const columns = if (row < dma_events.len)
            try dma_binding.machineColumns(dma_events[row], results)
        else
            dma_binding.inactiveColumns();
        const entry = policy_air.dmaPair(
            try dma_binding_component.Row(QM31).fromColumns(
                &lift(columns),
            ),
            relations,
        );
        dma_claim = try accumulate(dma_claim, entry);
        const storage = try core_air_utils.circleBitReversedIndex(
            dma_log_size,
            row,
        );
        writeSecure(&out.dma_columns, storage, dma_claim);
    }

    var ppu_claim = QM31.zero();
    for (0..ppu_size) |row| {
        const storage = try core_air_utils.circleBitReversedIndex(
            ppu_log_size,
            row,
        );
        const columns = if (row < ppu_events.len)
            try ppu_binding.columns(ppu_events[row])
        else
            ppu_binding.inactiveColumns();
        const entry = policy_air.ppuPair(
            try ppu_binding_component.Row(QM31).fromColumns(
                &lift(columns),
            ),
            .{
                QM31.fromBase(
                    witness.main[policy_air.VRAM_SELECTOR][storage],
                ),
                QM31.fromBase(
                    witness.main[policy_air.OAM_SELECTOR][storage],
                ),
            },
            relations,
        );
        ppu_claim = try accumulate(ppu_claim, entry);
        writeSecure(&out.ppu_columns, storage, ppu_claim);
    }
    out.claims = .{ .dma = dma_claim, .ppu = ppu_claim };
    try verifyCancellation(out.claims);
    return out;
}

const AccessClass = enum(usize) { vram, oam };

fn accessClass(address: u16) ?AccessClass {
    if (address >= VRAM_START and address <= VRAM_END) return .vram;
    if (address >= OAM_START and address <= OAM_END) return .oam;
    return null;
}

pub fn validate(
    results: []const machine.CartridgeStepResult,
    ppu_trace: ppu_binding.Trace,
    dma_trace: dma_binding.Trace,
) Error!void {
    if (ppu_trace.rows.len == 0) return error.InvalidPpuPolicyTrace;
    try validateTiming(ppu_trace.rows[0].transition.before);

    var cycle_count: usize = 0;
    var last_request_mcycle: ?u32 = null;
    for (ppu_trace.rows) |row| {
        try validateRequestClock(
            &last_request_mcycle,
            row.mcycle,
            row.transition.interrupts.vblank,
            row.transition.interrupts.stat,
        );
        switch (row.provenance) {
            .execution_tick => |tick| {
                if (tick.phase != 0) continue;
                try validateTiming(row.transition.before);

                const position = tick.position;
                if (position.execution_row >= results.len)
                    return error.InvalidPpuPolicyTrace;
                const result = results[position.execution_row];
                if (position.cycle >= result.m_cycles)
                    return error.InvalidPpuPolicyTrace;
                if (cycle_count >= dma_trace.rows.len)
                    return error.InvalidPpuPolicyTrace;
                const dma_row = dma_trace.rows[cycle_count];
                if (dma_row.mcycle != row.mcycle or
                    dma_row.provenance.execution_row != position.execution_row or
                    dma_row.provenance.cycle != position.cycle)
                {
                    return error.InvalidPpuPolicyTrace;
                }
                cycle_count += 1;
                try validateDmaTransfer(
                    row.transition.before,
                    dma_row.transition.transfer,
                );
                const instruction = result.instruction orelse continue;
                const access =
                    instruction.activeAccesses()[position.cycle] orelse continue;
                try validateAccess(
                    row.transition.before,
                    access.logical_address,
                );
            },
            .execution_write, .detached => {},
        }
    }

    var expected_cycles: usize = 0;
    for (results) |result|
        expected_cycles = std.math.add(
            usize,
            expected_cycles,
            result.m_cycles,
        ) catch return error.InvalidPpuPolicyTrace;
    if (cycle_count != expected_cycles or
        dma_trace.rows.len != expected_cycles)
        return error.InvalidPpuPolicyTrace;
}

fn validateRequestClock(
    last_request_mcycle: *?u32,
    mcycle: u32,
    vblank: bool,
    stat: bool,
) Error!void {
    if (!vblank and !stat) return;
    if (last_request_mcycle.* == mcycle)
        return error.UnsupportedMultiplePpuIfRequests;
    last_request_mcycle.* = mcycle;
}

fn validateDmaTransfer(
    timing: runner.ppu_timing.State,
    transfer: ?runner.dma.Transfer,
) Error!void {
    const source = (transfer orelse return).source_address;
    _ = timing;
    if (source >= VRAM_START and source <= VRAM_END)
        return error.UnsupportedVramDmaPpuConflict;
}

fn validateTiming(timing: runner.ppu_timing.State) Error!void {
    if (timing.stat_enable & 0x1 != 0)
        return error.UnsupportedHblankStatInterrupt;
}

fn validateAccess(
    timing: runner.ppu_timing.State,
    address: u16,
) Error!void {
    if (address == runner.ppu_mmio.STAT_ADDRESS) {
        if (!hasStableMode(timing))
            return error.UnsupportedVariableMode3Access;
        return;
    }
    if (address >= VRAM_START and address <= VRAM_END) {
        if (!vramAccessible(timing))
            return error.UnsupportedVariableMode3Access;
        return;
    }
    if (address >= OAM_START and address <= OAM_END and
        !oamAccessible(timing))
    {
        return error.UnsupportedVariableMode3Access;
    }
}

fn hasStableMode(timing: runner.ppu_timing.State) bool {
    if (!timing.lcd_enabled or
        timing.line >= runner.ppu_timing.VISIBLE_LINES)
    {
        return true;
    }
    if (timing.startup_line) return false;
    return timing.dot < runner.ppu_timing.MODE2_DOTS or
        timing.dot >= CERTAIN_HBLANK_DOT;
}

fn vramAccessible(timing: runner.ppu_timing.State) bool {
    return hasStableMode(timing);
}

fn oamAccessible(timing: runner.ppu_timing.State) bool {
    if (!timing.lcd_enabled or
        timing.line >= runner.ppu_timing.VISIBLE_LINES)
    {
        return true;
    }
    if (timing.startup_line) return false;
    return timing.dot >= CERTAIN_HBLANK_DOT;
}

fn accumulate(
    current: QM31,
    entry: dma_execution.Pair,
) !QM31 {
    return current
        .add(entry.n1.mul(entry.d1.inv() catch
            return error.PpuExecutionPolicyZeroDenominator))
        .add(entry.n2.mul(entry.d2.inv() catch
        return error.PpuExecutionPolicyZeroDenominator));
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidPpuExecutionPolicyLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn lift(values: anytype) [values.len]QM31 {
    var result: [values.len]QM31 = undefined;
    for (&result, values) |*target, source|
        target.* = QM31.fromBase(source);
    return result;
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

test "reduced PPU policy rejects every variable mode-3 CPU dependency" {
    const transfer = runner.ppu_timing.State{
        .lcd_enabled = true,
        .line = 12,
        .dot = 252,
    };
    inline for (.{
        runner.ppu_mmio.STAT_ADDRESS,
        @as(u16, VRAM_START),
        @as(u16, OAM_START),
    }) |address| {
        try std.testing.expectError(
            error.UnsupportedVariableMode3Access,
            validateAccess(transfer, address),
        );
    }
    var hblank_stat = transfer;
    hblank_stat.stat_enable = 1;
    try std.testing.expectError(
        error.UnsupportedHblankStatInterrupt,
        validateTiming(hblank_stat),
    );
}

test "reduced PPU policy admits only hardware-certain video access windows" {
    const mode2 = runner.ppu_timing.State{
        .lcd_enabled = true,
        .line = 8,
        .dot = 40,
    };
    try validateAccess(mode2, VRAM_START);
    try std.testing.expectError(
        error.UnsupportedVariableMode3Access,
        validateAccess(mode2, OAM_START),
    );

    const certain_hblank = runner.ppu_timing.State{
        .lcd_enabled = true,
        .line = 8,
        .dot = CERTAIN_HBLANK_DOT,
    };
    try validateAccess(certain_hblank, runner.ppu_mmio.STAT_ADDRESS);
    try validateAccess(certain_hblank, VRAM_START);
    try validateAccess(certain_hblank, OAM_START);

    const vblank = runner.ppu_timing.State{
        .lcd_enabled = true,
        .line = runner.ppu_timing.VISIBLE_LINES,
    };
    try validateAccess(vblank, runner.ppu_mmio.STAT_ADDRESS);
    try validateAccess(vblank, VRAM_START);
    try validateAccess(vblank, OAM_START);
}

test "reduced PPU policy rejects IF collisions and VRAM DMA" {
    var last_request: ?u32 = null;
    try validateRequestClock(&last_request, 7, true, true);
    try std.testing.expectError(
        error.UnsupportedMultiplePpuIfRequests,
        validateRequestClock(&last_request, 7, false, true),
    );
    try validateRequestClock(&last_request, 8, true, false);

    const transfer = runner.dma.Transfer{
        .source_address = VRAM_START,
        .destination_address = OAM_START,
        .value = 0,
    };
    try std.testing.expectError(
        error.UnsupportedVramDmaPpuConflict,
        validateDmaTransfer(.{
            .lcd_enabled = true,
            .line = 12,
        }, transfer),
    );
    try std.testing.expectError(
        error.UnsupportedVramDmaPpuConflict,
        validateDmaTransfer(.{
            .lcd_enabled = true,
            .line = runner.ppu_timing.VISIBLE_LINES,
        }, transfer),
    );
    try validateDmaTransfer(.{
        .lcd_enabled = true,
        .line = 12,
    }, .{
        .source_address = 0xc000,
        .destination_address = OAM_START,
        .value = 0,
    });
}
