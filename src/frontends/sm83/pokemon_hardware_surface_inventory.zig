//! Executable inventory of semantics not admitted by the v7 machine proof.
//!
//! Every field is pinned to zero for the promoted Pokemon profile. APU accesses
//! retain a separate exact positive count in the hardware-surface report, so
//! classifying them as owned cannot silently omit their device relation.

const std = @import("std");
const runner = @import("runner/mod.zig");

pub const IF_ADDRESS: u16 = 0xff0f;

pub const Origin = enum {
    instruction,
    interrupt_service_oam_bug,
    other,
};

pub const Counts = struct {
    stopped_boundary_rows: u64 = 0,
    stop_continuation_rows: u64 = 0,
    active_dma_halt_rows: u64 = 0,
    active_dma_stop_rows: u64 = 0,
    direct_cpu_if_accesses: u64 = 0,
    interrupt_service_oam_bug_mode2_cycles: u64 = 0,
    verifier_rejected_dma_source_accesses: u64 = 0,
    verifier_rejected_dma_oam_accesses: u64 = 0,
    unowned_mmio_addresses: u64 = 0,
    unowned_mmio_accesses: u64 = 0,

    pub fn targetAdmissible(self: Counts) bool {
        inline for (std.meta.fields(Counts)) |field| {
            if (@field(self, field.name) != 0) return false;
        }
        return true;
    }
};

pub const PINNED_EXPECTED = Counts{};

pub const Boundary = struct {
    before_stopped: bool,
    after_stopped: bool,
    before_halted: bool,
    after_halted: bool,
    dma_before_active: bool,
    dma_after_active: bool,
};

pub const Cycle = struct {
    origin: Origin,
    ppu_mode: runner.ppu_timing.Mode,
    access: ?runner.cartridge_memory.Access,
    verifier_owned_mmio: bool,
};

pub fn recordBoundary(counts: *Counts, boundary: Boundary) void {
    counts.stopped_boundary_rows += @intFromBool(
        boundary.before_stopped or boundary.after_stopped,
    );
    counts.stop_continuation_rows += @intFromBool(boundary.before_stopped);
    counts.active_dma_halt_rows += @intFromBool(
        (boundary.before_halted and boundary.dma_before_active) or
            (boundary.after_halted and boundary.dma_after_active),
    );
    counts.active_dma_stop_rows += @intFromBool(
        (boundary.before_stopped and boundary.dma_before_active) or
            (boundary.after_stopped and boundary.dma_after_active),
    );
}

pub fn recordCycle(counts: *Counts, cycle: Cycle) void {
    if (cycle.origin == .interrupt_service_oam_bug and
        cycle.ppu_mode == .oam)
    {
        counts.interrupt_service_oam_bug_mode2_cycles += 1;
    }
    const access = cycle.access orelse return;
    switch (access.dma_class) {
        .allowed => {},
        .blocked_source_bus => counts.verifier_rejected_dma_source_accesses += 1,
        .blocked_oam => counts.verifier_rejected_dma_oam_accesses += 1,
    }
    if (cycle.origin == .instruction and
        access.logical_address == IF_ADDRESS)
    {
        counts.direct_cpu_if_accesses += 1;
    }
    if (access.logical_address >= 0xff00 and
        access.logical_address <= 0xff7f and
        !cycle.verifier_owned_mmio)
    {
        counts.unowned_mmio_accesses += 1;
    }
}

pub fn setUnownedMmioAddresses(counts: *Counts, addresses: usize) !void {
    if (counts.unowned_mmio_addresses != 0)
        return error.UnownedMmioAddressesAlreadySet;
    counts.unowned_mmio_addresses = std.math.cast(u64, addresses) orelse
        return error.TooManyUnownedMmioAddresses;
}

pub fn validatePinned(counts: Counts) !void {
    if (!std.meta.eql(counts, PINNED_EXPECTED))
        return error.UnsupportedSemanticInventoryDrift;
}

test "SM83 Pokemon hardware surface classifies every unsupported semantic" {
    var counts = Counts{};
    recordBoundary(&counts, .{
        .before_stopped = true,
        .after_stopped = true,
        .before_halted = true,
        .after_halted = false,
        .dma_before_active = true,
        .dma_after_active = true,
    });
    recordCycle(&counts, .{
        .origin = .instruction,
        .ppu_mode = .hblank,
        .access = mockAccess(IF_ADDRESS, .blocked_source_bus),
        .verifier_owned_mmio = false,
    });
    recordCycle(&counts, .{
        .origin = .interrupt_service_oam_bug,
        .ppu_mode = .oam,
        .access = null,
        .verifier_owned_mmio = true,
    });
    recordCycle(&counts, .{
        .origin = .other,
        .ppu_mode = .vblank,
        .access = mockAccess(0xfe00, .blocked_oam),
        .verifier_owned_mmio = true,
    });
    try setUnownedMmioAddresses(&counts, 1);
    try std.testing.expectEqualDeep(Counts{
        .stopped_boundary_rows = 1,
        .stop_continuation_rows = 1,
        .active_dma_halt_rows = 1,
        .active_dma_stop_rows = 1,
        .direct_cpu_if_accesses = 1,
        .interrupt_service_oam_bug_mode2_cycles = 1,
        .verifier_rejected_dma_source_accesses = 1,
        .verifier_rejected_dma_oam_accesses = 1,
        .unowned_mmio_addresses = 1,
        .unowned_mmio_accesses = 1,
    }, counts);
}

test "SM83 Pokemon hardware surface unsupported counts fail closed field by field" {
    try validatePinned(PINNED_EXPECTED);
    inline for (std.meta.fields(Counts)) |field| {
        var mutated = PINNED_EXPECTED;
        @field(mutated, field.name) += 1;
        try std.testing.expectError(
            error.UnsupportedSemanticInventoryDrift,
            validatePinned(mutated),
        );
    }
    try std.testing.expect(PINNED_EXPECTED.targetAdmissible());
    try std.testing.expect((Counts{}).targetAdmissible());
}

fn mockAccess(
    address: u16,
    dma_class: runner.dma.CpuAccess,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = .read,
        .region = .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = 0xff,
        .dma_class = dma_class,
    };
}
