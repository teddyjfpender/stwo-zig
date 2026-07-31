//! Fail-closed projection from pinned SameBoy-native state into the current
//! canonical SM83 runner device boundaries.
//!
//! SameBoy carries more rendering and sub-cycle state than the frontend's
//! device leaves. A projection is returned only when every represented field
//! agrees with the committed system image and the smaller model can express
//! the checkpoint exactly.

const std = @import("std");
const runner = @import("../runner/mod.zig");
const apu_mmio = @import("../runner/apu_mmio.zig");

// SameBoy `Core/display.c:1530-1532` records that its mode state is four
// T-cycles late. On an ordinary visible line it installs mode 3 after 84 dots,
// while the frontend's fixed-line model deliberately uses the canonical
// 80-dot mode-2 boundary. Normalize that phase here; carrying SameBoy's raw
// accumulator directly makes every later frame edge one M-cycle early.
// VBlank's separate five-dot request ordering is modeled in `ppu_timing`;
// folding it into this checkpoint phase would shift every other PPU mode.
const FIXED_MODEL_PHASE_DOTS: i64 = 4;
const MODE_LATCH_PENDING: u8 = 0xff;

pub const Error =
    runner.joypad.ValidationError ||
    runner.ppu_mmio.ValidationError ||
    runner.dma.StateError ||
    apu_mmio.Error ||
    error{
        TimerImageMismatch,
        UnrepresentablePpuState,
        PpuImageMismatch,
        UnrepresentableDmaState,
    };

pub const TimerState = struct {
    display_cycles: i32,
    display_state: i32,
    div_cycles: i32,
    div_state: i32,
    div_counter: u16,
    reload_state: runner.timer.ReloadState,
    tima: u8,
    tma: u8,
    tac: u3,
    joypad_switching_delay: u8,
    joypad_switch_value: u8,
    raw: [64]u8,
};

pub const DmaState = struct {
    hdma_on: bool,
    hdma_on_hblank: bool,
    hdma_steps_left: u8,
    hdma_current_src: u16,
    hdma_current_dest: u16,
    current_dest: u8,
    last_read: u8,
    current_src: u16,
    cycles: u16,
    cycles_modulo: i8,
    ppu_vram_conflict: bool,
    ppu_vram_conflict_addr: u16,
    allow_hdma_on_wake: bool,
    restarting: bool,
    raw: [24]u8,
};

/// Retained SameBoy native-v15 APU section. It is deliberately opaque here:
/// `apu_mmio` projects only the CPU-visible fields and rejects a phase it
/// cannot derive from these committed bytes.
pub const ApuState = struct {
    raw: [apu_mmio.SAMEBOY_NATIVE_SIZE]u8,
};

/// Exact pinned SameBoy video section plus the timing fields consumed by the
/// current ROM-agnostic machine boundary. Retaining the complete section keeps
/// pixel-fetch and contention state available without misrepresenting it as
/// the frontend's intentionally smaller fixed-line model.
pub const PpuState = struct {
    position_in_line: u8,
    stat_interrupt_line: bool,
    current_line: u8,
    ly_for_comparison: u16,
    cycles_for_line: u16,
    mode_for_interrupt: u8,
    lyc_interrupt_line: bool,
    current_lcd_line: u8,
    oam_ppu_blocked: bool,
    vram_ppu_blocked: bool,
    lcd_x: u8,
    frame_parity_ticks: u32,
    raw: [464]u8,
};

pub fn toTimer(
    timer: TimerState,
    system: *const [runner.cartridge_memory.SYSTEM_SIZE]u8,
) Error!runner.timer.Timer {
    const projected = runner.timer.Timer{
        .div_counter = timer.div_counter,
        .tima = timer.tima,
        .tma = timer.tma,
        .tac = timer.tac,
        .reload_state = timer.reload_state,
    };
    if (system[0xff04] != projected.readDiv() or
        system[0xff05] != projected.tima or
        system[0xff06] != projected.tma or
        system[0xff07] & 0x07 != projected.tac)
    {
        return error.TimerImageMismatch;
    }
    return projected;
}

pub fn toJoypad(
    timer: TimerState,
    system: *const [runner.cartridge_memory.SYSTEM_SIZE]u8,
    pressed: u8,
) Error!runner.joypad.State {
    const p1 = system[runner.joypad.P1_ADDRESS];
    const pending_selection: u2 = if (timer.joypad_switching_delay == 0)
        @truncate(p1 >> 4)
    else
        @truncate(timer.joypad_switch_value >> 4);
    return runner.joypad.State.init(
        p1,
        pressed,
        pending_selection,
        timer.joypad_switching_delay,
    );
}

pub fn toApuMmio(
    apu: ApuState,
    system: *const [runner.cartridge_memory.SYSTEM_SIZE]u8,
) apu_mmio.Error!apu_mmio.State {
    return apu_mmio.State.fromSameBoyNative(
        system[0xff00..0xff40],
        &apu.raw,
    );
}

pub fn toPpuMmio(
    timer: TimerState,
    ppu: PpuState,
    system: *const [runner.cartridge_memory.SYSTEM_SIZE]u8,
    interrupt_flags: u8,
) Error!runner.ppu_mmio.State {
    if (@mod(timer.display_cycles, 2) != 0 or
        ppu.oam_ppu_blocked or
        ppu.vram_ppu_blocked)
    {
        return error.UnrepresentablePpuState;
    }
    // The 0xff sentinel is SameBoy's state before the delayed mode latch is
    // installed, so its accumulator has not acquired the four-dot lag yet.
    const phase_dots: i64 = if (ppu.mode_for_interrupt == MODE_LATCH_PENDING)
        0
    else
        FIXED_MODEL_PHASE_DOTS;
    const derived_dot =
        @as(i64, ppu.cycles_for_line) +
        @divTrunc(@as(i64, timer.display_cycles), 2) -
        phase_dots;
    if (derived_dot < 0 or
        derived_dot >= runner.ppu_timing.DOTS_PER_LINE or
        ppu.current_line != ppu.current_lcd_line)
    {
        return error.UnrepresentablePpuState;
    }

    const lcdc = system[runner.ppu_mmio.LCDC_ADDRESS];
    const stat = system[runner.ppu_mmio.STAT_ADDRESS];
    const timing = runner.ppu_timing.State{
        .lcd_enabled = lcdc & 0x80 != 0,
        .line = ppu.current_line,
        .dot = @intCast(derived_dot),
        .startup_line = false,
        .lyc = system[runner.ppu_mmio.LYC_ADDRESS],
        .stat_enable = @truncate(stat >> 3),
        .coincidence = stat & 0x04 != 0,
        .lyc_interrupt_line = ppu.lyc_interrupt_line,
        .stat_interrupt_line = ppu.stat_interrupt_line,
    };
    const projected = try runner.ppu_mmio.State.restore(.{
        .timing = timing,
        .lcdc = lcdc,
        .scy = system[runner.ppu_mmio.SCY_ADDRESS],
        .scx = system[runner.ppu_mmio.SCX_ADDRESS],
        .wy = system[runner.ppu_mmio.WY_ADDRESS],
        .interrupt_flags = interrupt_flags,
    });

    const expected_comparison: ?u16 =
        if (!timing.lcd_enabled)
            null
        else if (timing.line != runner.ppu_timing.LINES_PER_FRAME - 1)
            timing.line
        else if (timing.dot < 2)
            runner.ppu_timing.LINES_PER_FRAME - 2
        else if (timing.dot < 6)
            runner.ppu_timing.LINES_PER_FRAME - 1
        else
            null;
    if (expected_comparison) |value| {
        if (ppu.ly_for_comparison != value)
            return error.UnrepresentablePpuState;
    } else if (timing.lcd_enabled and
        ppu.ly_for_comparison != std.math.maxInt(u16))
    {
        return error.UnrepresentablePpuState;
    }

    if ((ppu.mode_for_interrupt != MODE_LATCH_PENDING and
        ppu.mode_for_interrupt != @intFromEnum(timing.mode())) or
        system[runner.ppu_mmio.STAT_ADDRESS] != timing.readStat() or
        system[runner.ppu_mmio.LY_ADDRESS] != timing.readLy())
    {
        return error.PpuImageMismatch;
    }
    return projected;
}

pub fn toDma(
    dma: DmaState,
    system: *const [runner.cartridge_memory.SYSTEM_SIZE]u8,
    initial_mcycle: u32,
) Error!runner.dma.State {
    if (dma.hdma_on or
        dma.hdma_on_hblank or
        dma.hdma_steps_left != 0 or
        dma.ppu_vram_conflict)
    {
        return error.UnrepresentableDmaState;
    }
    const page = system[runner.dma.DMA_ADDRESS];
    const phase: runner.dma.Phase = switch (dma.current_dest) {
        0xa1 => .idle,
        0xff => .startup,
        0xa0 => .finishing,
        0x00...0x9f => .transfer,
        else => return error.UnrepresentableDmaState,
    };
    const copied: u8 = switch (phase) {
        .idle, .startup => 0,
        .transfer => dma.current_dest,
        .finishing => runner.dma.OAM_LENGTH,
    };
    if (phase == .idle) {
        if (dma.restarting)
            return error.UnrepresentableDmaState;
    } else {
        const expected_src =
            (@as(u16, page) << 8) + @as(u16, copied);
        if (dma.current_src != expected_src or
            dma.cycles != 0 or
            dma.cycles_modulo != 0)
        {
            return error.UnrepresentableDmaState;
        }
    }

    const projected = runner.dma.State{
        .clock = initial_mcycle,
        .page = page,
        .copied = copied,
        .phase = phase,
        .restarting = dma.restarting,
    };
    try projected.validate();
    return projected;
}
