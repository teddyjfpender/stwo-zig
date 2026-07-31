//! Commitment geometry for the complete cartridge-machine environment.
//!
//! The v3 environment and complete v6 machine geometry remain exact prefixes.
//! V7 appends the APU binding and ordered execution lookup columns.

const std = @import("std");
const environment = @import("environment_statement.zig");
const scheduler_component = @import("air/scheduler_component.zig");
const scheduler_binding = @import("air/scheduler_binding.zig");
const scheduler_memory = @import("air/scheduler_memory_lookup.zig");
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");
const apu_binding = @import("air/apu_binding.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");

pub const PPU_FIRST_PREPROCESSED: usize =
    environment.N_PREPROCESSED_COLUMNS;
pub const PPU_LAST_PREPROCESSED: usize =
    PPU_FIRST_PREPROCESSED + 1;
pub const DMA_FIRST_PREPROCESSED: usize =
    PPU_LAST_PREPROCESSED + 1;
pub const DMA_LAST_PREPROCESSED: usize =
    DMA_FIRST_PREPROCESSED + 1;
pub const APU_FIRST_PREPROCESSED: usize =
    DMA_LAST_PREPROCESSED + 1;
pub const APU_LAST_PREPROCESSED: usize =
    APU_FIRST_PREPROCESSED + 1;
pub const N_PREPROCESSED_COLUMNS: usize =
    APU_LAST_PREPROCESSED + 1;

pub const SCHEDULER_MAIN_OFFSET: usize =
    environment.N_MAIN_COLUMNS;
pub const SCHEDULER_PROVENANCE_MAIN_OFFSET: usize =
    SCHEDULER_MAIN_OFFSET + scheduler_component.N_MAIN_COLUMNS;
pub const SCHEDULER_MEMORY_MAIN_OFFSET: usize =
    SCHEDULER_PROVENANCE_MAIN_OFFSET +
    scheduler_binding.N_PROVENANCE_COLUMNS;
pub const SERVICE_MEMORY_MAIN_OFFSET: usize =
    SCHEDULER_MEMORY_MAIN_OFFSET + scheduler_memory.N_MAIN_COLUMNS;
pub const PPU_BINDING_MAIN_OFFSET: usize =
    SERVICE_MEMORY_MAIN_OFFSET + service_memory.N_MAIN_COLUMNS;
pub const PPU_AUXILIARY_MAIN_OFFSET: usize =
    PPU_BINDING_MAIN_OFFSET + ppu_binding.N_MAIN_COLUMNS;
pub const PPU_IF_MAIN_OFFSET: usize =
    PPU_AUXILIARY_MAIN_OFFSET + 1;
pub const PPU_EXECUTION_POLICY_MAIN_OFFSET: usize =
    PPU_IF_MAIN_OFFSET + ppu_if.N_MAIN_COLUMNS;
pub const DMA_BINDING_MAIN_OFFSET: usize =
    PPU_EXECUTION_POLICY_MAIN_OFFSET +
    ppu_execution_policy.N_MAIN_COLUMNS;
pub const DMA_MEMORY_MAIN_OFFSET: usize =
    DMA_BINDING_MAIN_OFFSET + dma_binding.N_MAIN_COLUMNS;
pub const APU_BINDING_MAIN_OFFSET: usize =
    DMA_MEMORY_MAIN_OFFSET + dma_memory.N_MAIN_COLUMNS;
pub const APU_EXECUTION_ORDER_MAIN_OFFSET: usize =
    APU_BINDING_MAIN_OFFSET + apu_binding.layout.N_MAIN_COLUMNS;
pub const APU_MCYCLE_MAIN_OFFSET: usize =
    APU_EXECUTION_ORDER_MAIN_OFFSET + 1;
pub const APU_ORDER_MAIN_OFFSET: usize =
    APU_MCYCLE_MAIN_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = APU_ORDER_MAIN_OFFSET + 1;

pub const SCHEDULER_MEMORY_INTERACTION_OFFSET: usize =
    environment.N_INTERACTION_COLUMNS;
pub const SERVICE_MEMORY_INTERACTION_OFFSET: usize =
    SCHEDULER_MEMORY_INTERACTION_OFFSET +
    scheduler_memory.N_INTERACTION_COLUMNS;
pub const PPU_MMIO_EXECUTION_INTERACTION_OFFSET: usize =
    SERVICE_MEMORY_INTERACTION_OFFSET +
    service_memory.N_INTERACTION_COLUMNS;
pub const PPU_MMIO_PPU_INTERACTION_OFFSET: usize =
    PPU_MMIO_EXECUTION_INTERACTION_OFFSET +
    ppu_mmio.N_EXECUTION_INTERACTION_COLUMNS;
pub const PPU_IF_INTERACTION_OFFSET: usize =
    PPU_MMIO_PPU_INTERACTION_OFFSET +
    ppu_mmio.N_PPU_INTERACTION_COLUMNS;
pub const PPU_POLICY_DMA_INTERACTION_OFFSET: usize =
    PPU_IF_INTERACTION_OFFSET + ppu_if.N_INTERACTION_COLUMNS;
pub const PPU_POLICY_PPU_INTERACTION_OFFSET: usize =
    PPU_POLICY_DMA_INTERACTION_OFFSET +
    ppu_execution_policy.N_DMA_INTERACTION_COLUMNS;
pub const DMA_EXECUTION_INTERACTION_OFFSET: usize =
    PPU_POLICY_PPU_INTERACTION_OFFSET +
    ppu_execution_policy.N_PPU_INTERACTION_COLUMNS;
pub const DMA_DMA_INTERACTION_OFFSET: usize =
    DMA_EXECUTION_INTERACTION_OFFSET +
    dma_execution.N_EXECUTION_INTERACTION_COLUMNS;
pub const DMA_MEMORY_INTERACTION_OFFSET: usize =
    DMA_DMA_INTERACTION_OFFSET +
    dma_execution.N_DMA_INTERACTION_COLUMNS;
pub const APU_EXECUTION_INTERACTION_OFFSET: usize =
    DMA_MEMORY_INTERACTION_OFFSET + dma_memory.N_INTERACTION_COLUMNS;
pub const APU_APU_INTERACTION_OFFSET: usize =
    APU_EXECUTION_INTERACTION_OFFSET +
    apu_execution.N_EXECUTION_INTERACTION_COLUMNS;
pub const N_INTERACTION_COLUMNS: usize =
    APU_APU_INTERACTION_OFFSET + apu_execution.N_APU_INTERACTION_COLUMNS;

pub fn preprocessedLogSizes(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    observation_log_size: u32,
    ppu_log_size: u32,
    dma_log_size: u32,
    apu_log_size: u32,
) [N_PREPROCESSED_COLUMNS]u32 {
    var out: [N_PREPROCESSED_COLUMNS]u32 = undefined;
    const prefix = environment.preprocessedLogSizes(
        execution_log_size,
        joypad_log_size,
        timer_log_size,
        observation_log_size,
    );
    @memcpy(out[0..environment.N_PREPROCESSED_COLUMNS], &prefix);
    out[PPU_FIRST_PREPROCESSED] = ppu_log_size;
    out[PPU_LAST_PREPROCESSED] = ppu_log_size;
    out[DMA_FIRST_PREPROCESSED] = dma_log_size;
    out[DMA_LAST_PREPROCESSED] = dma_log_size;
    out[APU_FIRST_PREPROCESSED] = apu_log_size;
    out[APU_LAST_PREPROCESSED] = apu_log_size;
    return out;
}

pub fn mainLogSizes(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    observation_log_size: u32,
    ppu_log_size: u32,
    dma_log_size: u32,
    apu_log_size: u32,
) [N_MAIN_COLUMNS]u32 {
    var out: [N_MAIN_COLUMNS]u32 = undefined;
    const prefix = environment.mainLogSizes(
        execution_log_size,
        joypad_log_size,
        timer_log_size,
        observation_log_size,
    );
    @memcpy(out[0..environment.N_MAIN_COLUMNS], &prefix);
    @memset(
        out[SCHEDULER_MAIN_OFFSET..PPU_BINDING_MAIN_OFFSET],
        execution_log_size,
    );
    @memset(
        out[PPU_BINDING_MAIN_OFFSET..DMA_BINDING_MAIN_OFFSET],
        ppu_log_size,
    );
    @memset(
        out[DMA_BINDING_MAIN_OFFSET..APU_BINDING_MAIN_OFFSET],
        dma_log_size,
    );
    @memset(
        out[APU_BINDING_MAIN_OFFSET..APU_EXECUTION_ORDER_MAIN_OFFSET],
        apu_log_size,
    );
    out[APU_EXECUTION_ORDER_MAIN_OFFSET] = execution_log_size;
    @memset(out[APU_MCYCLE_MAIN_OFFSET..], apu_log_size);
    return out;
}

pub fn interactionLogSizes(
    execution_log_size: u32,
    joypad_log_size: u32,
    timer_log_size: u32,
    observation_log_size: u32,
    ppu_log_size: u32,
    dma_log_size: u32,
    apu_log_size: u32,
) [N_INTERACTION_COLUMNS]u32 {
    var out: [N_INTERACTION_COLUMNS]u32 = undefined;
    const prefix = environment.interactionLogSizes(
        execution_log_size,
        joypad_log_size,
        timer_log_size,
        observation_log_size,
    );
    @memcpy(out[0..environment.N_INTERACTION_COLUMNS], &prefix);
    @memset(
        out[SCHEDULER_MEMORY_INTERACTION_OFFSET..PPU_MMIO_EXECUTION_INTERACTION_OFFSET],
        execution_log_size,
    );
    @memset(
        out[PPU_MMIO_EXECUTION_INTERACTION_OFFSET..PPU_MMIO_PPU_INTERACTION_OFFSET],
        execution_log_size,
    );
    @memset(
        out[PPU_MMIO_PPU_INTERACTION_OFFSET..PPU_POLICY_DMA_INTERACTION_OFFSET],
        ppu_log_size,
    );
    @memset(
        out[PPU_POLICY_DMA_INTERACTION_OFFSET..PPU_POLICY_PPU_INTERACTION_OFFSET],
        dma_log_size,
    );
    @memset(
        out[PPU_POLICY_PPU_INTERACTION_OFFSET..DMA_EXECUTION_INTERACTION_OFFSET],
        ppu_log_size,
    );
    @memset(
        out[DMA_EXECUTION_INTERACTION_OFFSET..DMA_DMA_INTERACTION_OFFSET],
        execution_log_size,
    );
    @memset(
        out[DMA_DMA_INTERACTION_OFFSET..APU_EXECUTION_INTERACTION_OFFSET],
        dma_log_size,
    );
    @memset(
        out[APU_EXECUTION_INTERACTION_OFFSET..APU_APU_INTERACTION_OFFSET],
        execution_log_size,
    );
    @memset(out[APU_APU_INTERACTION_OFFSET..], apu_log_size);
    return out;
}

test "machine environment geometry preserves v3 and orders machine tails" {
    const preprocessed = preprocessedLogSizes(4, 5, 6, 7, 8, 9, 10);
    const main = mainLogSizes(4, 5, 6, 7, 8, 9, 10);
    const interaction = interactionLogSizes(4, 5, 6, 7, 8, 9, 10);
    const expected_preprocessed =
        environment.preprocessedLogSizes(4, 5, 6, 7);
    const expected_main = environment.mainLogSizes(4, 5, 6, 7);
    const expected_interaction =
        environment.interactionLogSizes(4, 5, 6, 7);
    try std.testing.expectEqualSlices(
        u32,
        &expected_preprocessed,
        preprocessed[0..environment.N_PREPROCESSED_COLUMNS],
    );
    try std.testing.expectEqualSlices(
        u32,
        &expected_main,
        main[0..environment.N_MAIN_COLUMNS],
    );
    try std.testing.expectEqualSlices(
        u32,
        &expected_interaction,
        interaction[0..environment.N_INTERACTION_COLUMNS],
    );
    try std.testing.expectEqual(@as(u32, 8), main[PPU_IF_MAIN_OFFSET]);
    try std.testing.expectEqual(
        @as(u32, 4),
        interaction[PPU_MMIO_EXECUTION_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 9),
        interaction[DMA_MEMORY_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 10),
        preprocessed[APU_LAST_PREPROCESSED],
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        main[APU_EXECUTION_ORDER_MAIN_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 10),
        interaction[APU_APU_INTERACTION_OFFSET],
    );
}
