//! Field-canonical ordering phases for mutable cartridge memory.

const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;

pub const PHASES: u32 = 10;
pub const ACTION_PHASE: u32 = 0;
pub const SCHEDULER_PHASE: u32 = 1;
pub const CPU_PHASE: u32 = 2;
pub const SERVICE_RESAMPLE_PHASE: u32 = 3;
pub const SERVICE_ACK_PHASE: u32 = 4;
pub const TIMER_PHASE: u32 = 5;
pub const TICK_PHASE: u32 = TIMER_PHASE;
pub const JOYPAD_TICK_PHASE: u32 = 6;
pub const PPU_PHASE: u32 = 7;
pub const DMA_PHASE: u32 = 8;
pub const OBSERVATION_PHASE: u32 = 9;
pub const MAX_FINAL_MCYCLE: u32 = (M31_MODULUS - 1) / PHASES;

pub fn phaseClock(mcycle: u32, phase: u32) !u32 {
    if (phase >= PHASES) return error.InvalidMemoryClockPhase;
    const scaled = std.math.mul(u32, mcycle, PHASES) catch
        return error.MemoryClockOverflow;
    const result = std.math.add(u32, scaled, phase + 1) catch
        return error.MemoryClockOverflow;
    if (result >= M31_MODULUS) return error.MemoryClockOutsideField;
    return result;
}

pub fn cpuClock(mcycle: u32, cycle: usize) !u32 {
    const absolute = std.math.add(u32, mcycle, @intCast(cycle)) catch
        return error.MemoryClockOverflow;
    return phaseClock(absolute, CPU_PHASE);
}

pub fn fieldClock(
    comptime S: type,
    mcycle: S,
    phase: u32,
) S {
    return mcycle.mul(constant(S, PHASES))
        .add(constant(S, phase + 1));
}

fn constant(comptime S: type, value: u32) S {
    const base = M31.fromCanonical(value);
    if (S == M31) return base;
    return S.fromBase(base);
}
