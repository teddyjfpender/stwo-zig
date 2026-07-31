//! Reproducible hardware-surface audit for the pinned Pokemon battle prefix.
//!
//! The audit streams the three canonical replay chunks once and records CPU
//! accesses plus proof-relevant scheduler, PPU, and DMA boundary events. DMA
//! source/destination traffic remains tied to the replay fixture's exact totals.

const std = @import("std");
const replay = @import("pokemon_checkpoint_replay.zig");
const runner = @import("runner/mod.zig");
const apu_surface = @import("pokemon_hardware_surface_apu.zig");
const cycle_projection = @import("pokemon_hardware_surface_cycle.zig");
const unsupported = @import("pokemon_hardware_surface_inventory.zig");

const Access = runner.cartridge_memory.Access;
const Action = runner.cartridge_memory.Action;
const PpuState = runner.ppu_mmio.State;

pub const AccessCounts = struct {
    reads: u64 = 0,
    writes: u64 = 0,

    pub fn total(self: AccessCounts) u64 {
        return self.reads + self.writes;
    }

    fn add(self: *AccessCounts, action: Action) void {
        switch (action) {
            .read => self.reads += 1,
            .write => self.writes += 1,
        }
    }

    fn merge(self: *AccessCounts, other: AccessCounts) void {
        self.reads += other.reads;
        self.writes += other.writes;
    }
};

pub const Footprint = struct {
    touched_addresses: usize = 0,
    accesses: AccessCounts = .{},
};

pub const UnsafeCases = struct {
    dma_source_bus_blocked: u64 = 0,
    dma_oam_blocked: u64 = 0,
    hardware_blocked_vram: u64 = 0,
    hardware_blocked_oam: u64 = 0,
    reduced_ppu_policy_rejected: u64 = 0,
    stat_access_reduced_policy_rejected: u64 = 0,
    hblank_stat_enabled_mcycles: u64 = 0,
    render_register_write_outside_vblank: u64 = 0,
    ff46_write_outside_vblank: u64 = 0,
    vram_source_dma_starts: u64 = 0,
};

pub const FinalApuKnowledge = apu_surface.FinalKnowledge;
pub const ApuSemantics = apu_surface.Semantics;
pub const UnsupportedSemanticEvents = unsupported.Counts;

pub const Report = struct {
    chunks: usize = 0,
    rows: usize = 0,
    mcycles: u64 = 0,
    callbacks: usize = 0,
    actions: usize = 0,
    all_cpu_accesses: u64 = 0,

    mmio: Footprint = .{},
    dedicated_mmio: Footprint = .{},
    generic_mmio: Footprint = .{},
    apu: Footprint = .{},
    wave: Footprint = .{},
    ppu_dedicated: Footprint = .{},
    vram: Footprint = .{},
    oam: Footprint = .{},

    scy_writes: u64 = 0,
    scx_writes: u64 = 0,
    wy_writes: u64 = 0,
    vram_vblank_writes: u64 = 0,

    ff46_writes: u64 = 0,
    ff46_c3_writes: u64 = 0,
    dma_source_bytes: usize = 0,
    dma_allowed_cpu_accesses: u64 = 0,
    apu_semantics: ApuSemantics = .{},

    unsafe: UnsafeCases = .{},
    unsupported_semantics: UnsupportedSemanticEvents = .{},

    finish_lookahead_rows: usize = 0,
    finish_lookahead_mcycles: u32 = 0,
    finish_oracle_records: usize = 0,
};

pub const EXPECTED = Report{
    .chunks = 3,
    .rows = 393_216,
    .mcycles = 446_882,
    .callbacks = 42_302,
    .actions = 2,
    .all_cpu_accesses = 86_311,
    .mmio = .{
        .touched_addresses = 40,
        .accesses = .{ .reads = 470, .writes = 383 },
    },
    .dedicated_mmio = .{
        .touched_addresses = 40,
        .accesses = .{ .reads = 470, .writes = 383 },
    },
    .generic_mmio = .{},
    .apu = .{
        .touched_addresses = 18,
        .accesses = .{ .reads = 20, .writes = 128 },
    },
    .wave = .{
        .touched_addresses = 16,
        .accesses = .{ .writes = 80 },
    },
    .ppu_dedicated = .{
        .touched_addresses = 3,
        .accesses = .{ .writes = 75 },
    },
    .vram = .{
        .touched_addresses = 376,
        .accesses = .{ .writes = 2_896 },
    },
    .oam = .{},
    .scy_writes = 25,
    .scx_writes = 25,
    .wy_writes = 25,
    .vram_vblank_writes = 2_896,
    .ff46_writes = 25,
    .ff46_c3_writes = 25,
    .dma_source_bytes = 4_000,
    .dma_allowed_cpu_accesses = 86_311,
    .apu_semantics = .{
        .events = 228,
        .matching_ff25_reads = 20,
        .writes = 208,
        .wave_writes = 80,
        .wave_bursts = 5,
        .ordered_wave_bursts = 5,
        .dac_off_six_mcycles_before = 5,
        .inactive_wave_bursts = 5,
        .final_knowledge = .unknown_channel_and_wave,
    },
    .unsafe = .{},
    .unsupported_semantics = unsupported.PINNED_EXPECTED,
    .finish_lookahead_rows = 7_468,
    .finish_lookahead_mcycles = 7_475,
    .finish_oracle_records = 42_303,
};

pub const BENCHMARK_EXPECTED = Report{
    .chunks = 3,
    .rows = 786_432,
    .mcycles = 1_505_332,
    .callbacks = 601_239,
    .actions = 33,
    .all_cpu_accesses = 1_157_525,
    .mmio = .{
        .touched_addresses = 10,
        .accesses = .{ .reads = 239, .writes = 771 },
    },
    .dedicated_mmio = .{
        .touched_addresses = 6,
        .accesses = .{ .reads = 239, .writes = 711 },
    },
    // Write-only BGP/OBP0/OBP1/WX presentation latches are committed by the
    // system-memory relation; no framebuffer or pixel behavior is claimed.
    .generic_mmio = .{
        .touched_addresses = 4,
        .accesses = .{ .writes = 60 },
    },
    .ppu_dedicated = .{
        .touched_addresses = 4,
        .accesses = .{ .reads = 3, .writes = 272 },
    },
    .vram = .{
        .touched_addresses = 1_288,
        .accesses = .{ .writes = 7_912 },
    },
    .scy_writes = 85,
    .scx_writes = 85,
    .wy_writes = 102,
    .vram_vblank_writes = 7_912,
    .ff46_writes = 85,
    .ff46_c3_writes = 85,
    .dma_source_bytes = 13_600,
    .dma_allowed_cpu_accesses = 1_157_525,
    .apu_semantics = .{ .final_knowledge = .fully_known },
    // These writes only alter omitted pixels. CPU OAM access, unsafe VRAM,
    // DMA bus rejection, STAT timing, and unowned MMIO remain exactly zero.
    .unsafe = .{
        .render_register_write_outside_vblank = 17,
        .ff46_write_outside_vblank = 1,
    },
    .unsupported_semantics = unsupported.PINNED_EXPECTED,
    .finish_lookahead_rows = 3_228,
    .finish_lookahead_mcycles = 3_235,
    .finish_oracle_records = 601_240,
};

pub const AuditError = error{
    DisconnectedDmaChunks,
    DisconnectedPpuChunks,
    InvalidAccessMetadata,
    InvalidDmaTrace,
    McycleCountMismatch,
    PokemonHardwareSurfaceDrift,
};

const MmioClass = enum {
    dedicated_joypad,
    dedicated_timer,
    dedicated_ppu,
    dedicated_dma,
    dedicated_apu,
    dedicated_wave,
    reduced_render_latch,
    generic_other,

    fn dedicated(self: MmioClass) bool {
        return switch (self) {
            .dedicated_joypad,
            .dedicated_timer,
            .dedicated_ppu,
            .dedicated_dma,
            .dedicated_apu,
            .dedicated_wave,
            => true,
            else => false,
        };
    }
};

const Collector = struct {
    report: Report = .{},
    mmio: [0x80]AccessCounts = [_]AccessCounts{.{}} ** 0x80,
    vram: [0x2000]AccessCounts = [_]AccessCounts{.{}} ** 0x2000,
    oam: [0xa0]AccessCounts = [_]AccessCounts{.{}} ** 0xa0,
    mmio_classes: [0x80]?MmioClass = [_]?MmioClass{null} ** 0x80,

    fn record(
        self: *Collector,
        access: Access,
        ppu: runner.ppu_timing.State,
    ) AuditError!void {
        self.report.all_cpu_accesses += 1;
        switch (access.dma_class) {
            .allowed => self.report.dma_allowed_cpu_accesses += 1,
            .blocked_source_bus => self.report.unsafe.dma_source_bus_blocked += 1,
            .blocked_oam => self.report.unsafe.dma_oam_blocked += 1,
        }

        const address = access.logical_address;
        if (address >= 0xff00 and address <= 0xff7f) {
            const index = address - 0xff00;
            const class = mmioClass(address);
            try validateRegion(access, class);
            self.mmio[index].add(access.action);
            if (self.mmio_classes[index]) |prior| {
                if (prior != class) return error.InvalidAccessMetadata;
            } else self.mmio_classes[index] = class;

            if (address == 0xff42 and access.action == .write)
                self.report.scy_writes += 1;
            if (address == 0xff43 and access.action == .write)
                self.report.scx_writes += 1;
            if (address == 0xff4a and access.action == .write)
                self.report.wy_writes += 1;
            if ((address == 0xff42 or address == 0xff43 or
                address == 0xff4a) and access.action == .write and
                ppu.mode() != .vblank)
            {
                self.report.unsafe
                    .render_register_write_outside_vblank += 1;
            }
            if (address == runner.ppu_mmio.STAT_ADDRESS and
                !stablePpuMode(ppu))
            {
                self.report.unsafe
                    .stat_access_reduced_policy_rejected += 1;
            }
            if (address == runner.dma.DMA_ADDRESS and
                access.action == .write)
            {
                self.report.ff46_writes += 1;
                self.report.ff46_c3_writes +=
                    @intFromBool(access.value == 0xc3);
                self.report.unsafe.vram_source_dma_starts +=
                    @intFromBool(access.value >= 0x80 and
                    access.value < 0xa0);
                self.report.unsafe.ff46_write_outside_vblank +=
                    @intFromBool(ppu.mode() != .vblank);
            }
        } else if (address >= 0x8000 and address <= 0x9fff) {
            if (access.region != .system)
                return error.InvalidAccessMetadata;
            self.vram[address - 0x8000].add(access.action);
            if (access.action == .write and ppu.mode() == .vblank)
                self.report.vram_vblank_writes += 1;
            self.report.unsafe.hardware_blocked_vram +=
                @intFromBool(ppu.mode() == .transfer);
            self.report.unsafe.reduced_ppu_policy_rejected +=
                @intFromBool(!reducedPpuPolicyAllows(ppu, address));
        } else if (address >= 0xfe00 and address <= 0xfe9f) {
            if (access.region != .system)
                return error.InvalidAccessMetadata;
            self.oam[address - 0xfe00].add(access.action);
            self.report.unsafe.hardware_blocked_oam +=
                @intFromBool(ppu.mode() == .oam or
                ppu.mode() == .transfer);
            self.report.unsafe.reduced_ppu_policy_rejected +=
                @intFromBool(!reducedPpuPolicyAllows(ppu, address));
        }
    }

    fn finish(self: *Collector, exact: bool) AuditError!Report {
        summarizeMmio(self);
        var unowned_addresses: usize = 0;
        for (self.mmio, self.mmio_classes) |counts, maybe_class| {
            if (counts.total() != 0 and maybe_class == .generic_other)
                unowned_addresses += 1;
        }
        unsupported.setUnownedMmioAddresses(
            &self.report.unsupported_semantics,
            unowned_addresses,
        ) catch return error.PokemonHardwareSurfaceDrift;
        self.report.vram = footprint(&self.vram);
        self.report.oam = footprint(&self.oam);
        if (exact) {
            try validateMmio(self.mmio);
            try validateVram(self.vram);
            for (self.oam) |counts|
                if (counts.total() != 0)
                    return error.PokemonHardwareSurfaceDrift;
            try validateReport(self.report);
        } else {
            try validateBenchmarkReducedMmio(self.mmio);
            try validateTargetReport(self.report);
        }
        return self.report;
    }
};

const AuditConfiguration = struct {
    profile: replay.Profile,
    rows: usize,
    expectations: []const replay.Expectation,
    exact: bool,
};

/// Replays and validates the complete pinned three-chunk hardware surface.
/// Artifact hashes, SameBoy callbacks, chunk counts, and adjacent machine
/// boundaries are inherited from `pokemon_checkpoint_replay.Session`.
pub fn audit(
    allocator: std.mem.Allocator,
    corpus_root: []const u8,
) !Report {
    return auditProfile(allocator, corpus_root, .{
        .profile = .visual,
        .rows = replay.DEFAULT_ROWS,
        .expectations = &replay.VERIFIED_PREFIX,
        .exact = true,
    });
}

pub fn auditBenchmark(
    allocator: std.mem.Allocator,
    corpus_root: []const u8,
) !Report {
    return auditProfile(allocator, corpus_root, .{
        .profile = .benchmark,
        .rows = 1 << 18,
        .expectations = &replay.BENCHMARK_VERIFIED_PREFIX,
        .exact = false,
    });
}

fn auditProfile(
    allocator: std.mem.Allocator,
    corpus_root: []const u8,
    configuration: AuditConfiguration,
) !Report {
    const collector = try allocator.create(Collector);
    defer allocator.destroy(collector);
    collector.* = .{};

    const session = try replay.Session.init(allocator, corpus_root, .{
        .profile = configuration.profile,
        .rows = configuration.rows,
    });
    defer session.deinit();
    var prior_ppu: ?PpuState = null;
    var prior_dma: ?runner.dma.State = null;
    var apu = apu_surface.Audit.init(try session.checkpoint.toApuMmio());

    for (configuration.expectations) |expected| {
        var chunk = try session.next(expected);
        errdefer chunk.deinit();
        const input = chunk.input();
        const summary = chunk.summary();
        var ppu = PpuState{
            .timing = input.initial_ppu.timing,
            .lcdc = input.initial_ppu.lcdc,
            .scy = input.initial_images.system.bytes[
                runner.ppu_mmio.SCY_ADDRESS
            ],
            .scx = input.initial_images.system.bytes[
                runner.ppu_mmio.SCX_ADDRESS
            ],
            .wy = input.initial_images.system.bytes[
                runner.ppu_mmio.WY_ADDRESS
            ],
            .interrupt_flags = input.results[0].before.interrupt_flags,
        };
        if (prior_ppu) |previous|
            if (!std.meta.eql(previous.timing, ppu.timing) or
                previous.lcdc != ppu.lcdc or previous.scy != ppu.scy or
                previous.scx != ppu.scx or previous.wy != ppu.wy)
            {
                return error.DisconnectedPpuChunks;
            };
        if (prior_dma) |previous|
            if (!std.meta.eql(previous, input.initial_dma))
                return error.DisconnectedDmaChunks;
        var dma = input.initial_dma;

        var observed_mcycles: u32 = 0;
        var observed_dma_sources: usize = 0;
        for (input.results) |result| {
            const dma_before = dma;
            for (0..result.m_cycles) |cycle| {
                collector.report.unsafe.hblank_stat_enabled_mcycles +=
                    @intFromBool(ppu.timing.stat_enable & 0x1 != 0);
                const maybe_access = cycle_projection.access(result, cycle);
                const transition = cycle_projection.advanceDma(
                    dma,
                    maybe_access,
                ) catch
                    return error.InvalidDmaTrace;
                dma = transition.after;
                observed_dma_sources += @intFromBool(
                    transition.transfer != null,
                );
                unsupported.recordCycle(
                    &collector.report.unsupported_semantics,
                    .{
                        .origin = cycle_projection.origin(result, cycle),
                        .ppu_mode = ppu.timing.mode(),
                        .access = maybe_access,
                        .verifier_owned_mmio = if (maybe_access) |access|
                            verifierOwnsMmio(access.logical_address)
                        else
                            true,
                    },
                );
                if (maybe_access) |access| {
                    try collector.record(access, ppu.timing);
                    const event_mcycle = std.math.add(
                        u32,
                        summary.initial_mcycle,
                        observed_mcycles,
                    ) catch return error.McycleCountMismatch;
                    apu.record(
                        &collector.report.apu_semantics,
                        access,
                        event_mcycle,
                    ) catch return error.PokemonHardwareSurfaceDrift;
                    if (access.region == .ppu_mmio and
                        access.action == .write)
                    {
                        _ = ppu.write(access.logical_address, access.value) catch return error.InvalidAccessMetadata;
                    }
                }
                _ = ppu.tickMcycle();
                observed_mcycles += 1;
            }
            unsupported.recordBoundary(
                &collector.report.unsupported_semantics,
                .{
                    .before_stopped = result.before.cpu.stopped,
                    .after_stopped = result.after.cpu.stopped,
                    .before_halted = result.before.cpu.halted,
                    .after_halted = result.after.cpu.halted,
                    .dma_before_active = dma_before.isActive(),
                    .dma_after_active = dma.isActive(),
                },
            );
        }
        if (observed_mcycles != summary.mcycles or
            observed_dma_sources != summary.dma_source_bytes)
        {
            return error.McycleCountMismatch;
        }
        prior_ppu = ppu;
        prior_dma = dma;

        collector.report.chunks += 1;
        collector.report.rows += summary.rows;
        collector.report.mcycles += summary.mcycles;
        collector.report.callbacks += summary.callbacks;
        collector.report.actions += summary.actions;
        collector.report.dma_source_bytes += summary.dma_source_bytes;
        chunk.deinit();
    }

    apu.finish(&collector.report.apu_semantics) catch
        return error.PokemonHardwareSurfaceDrift;
    const terminal = try session.finish();
    collector.report.finish_lookahead_rows = terminal.lookahead_rows;
    collector.report.finish_lookahead_mcycles = terminal.lookahead_mcycles;
    collector.report.finish_oracle_records = terminal.oracle_records;
    return collector.finish(configuration.exact);
}

fn verifierOwnsMmio(address: u16) bool {
    if (address < 0xff00 or address > 0xff7f) return true;
    return mmioClass(address) != .generic_other;
}

fn mmioClass(address: u16) MmioClass {
    return switch (address) {
        0xff00 => .dedicated_joypad,
        0xff04...0xff07 => .dedicated_timer,
        0xff40...0xff45, 0xff4a => .dedicated_ppu,
        0xff46 => .dedicated_dma,
        0xff47...0xff49, 0xff4b => .reduced_render_latch,
        0xff10...0xff26 => .dedicated_apu,
        0xff30...0xff3f => .dedicated_wave,
        else => .generic_other,
    };
}

fn validateRegion(access: Access, class: MmioClass) AuditError!void {
    const expected: runner.cartridge_memory.Region = switch (class) {
        .dedicated_joypad => .joypad_mmio,
        .dedicated_timer => .timer_mmio,
        .dedicated_ppu => .ppu_mmio,
        .dedicated_apu,
        .dedicated_wave,
        => .apu_mmio,
        .dedicated_dma,
        .reduced_render_latch,
        .generic_other,
        => .system,
    };
    if (access.region != expected or access.physical_offset != null)
        return error.InvalidAccessMetadata;
}

fn reducedPpuPolicyAllows(
    ppu: runner.ppu_timing.State,
    address: u16,
) bool {
    if (!ppu.lcd_enabled or ppu.line >= runner.ppu_timing.VISIBLE_LINES)
        return true;
    if (address >= 0x8000 and address <= 0x9fff) {
        return stablePpuMode(ppu);
    }
    if (address >= 0xfe00 and address <= 0xfe9f)
        return ppu.dot >= 384;
    return true;
}

fn stablePpuMode(ppu: runner.ppu_timing.State) bool {
    if (!ppu.lcd_enabled or ppu.line >= runner.ppu_timing.VISIBLE_LINES)
        return true;
    if (ppu.startup_line) return false;
    return ppu.dot < runner.ppu_timing.MODE2_DOTS or ppu.dot >= 384;
}

fn summarizeMmio(collector: *Collector) void {
    for (collector.mmio, collector.mmio_classes) |counts, maybe_class| {
        if (counts.total() == 0) continue;
        collector.report.mmio.touched_addresses += 1;
        collector.report.mmio.accesses.merge(counts);
        const class = maybe_class orelse unreachable;
        if (class.dedicated()) {
            collector.report.dedicated_mmio.touched_addresses += 1;
            collector.report.dedicated_mmio.accesses.merge(counts);
        } else {
            collector.report.generic_mmio.touched_addresses += 1;
            collector.report.generic_mmio.accesses.merge(counts);
        }
        switch (class) {
            .dedicated_apu => {
                collector.report.apu.touched_addresses += 1;
                collector.report.apu.accesses.merge(counts);
            },
            .dedicated_wave => {
                collector.report.wave.touched_addresses += 1;
                collector.report.wave.accesses.merge(counts);
            },
            .dedicated_ppu => {
                collector.report.ppu_dedicated.touched_addresses += 1;
                collector.report.ppu_dedicated.accesses.merge(counts);
            },
            else => {},
        }
    }
}

fn footprint(counts: []const AccessCounts) Footprint {
    var result = Footprint{};
    for (counts) |value| {
        if (value.total() == 0) continue;
        result.touched_addresses += 1;
        result.accesses.merge(value);
    }
    return result;
}

const MmioExpected = struct {
    address: u16,
    reads: u64 = 0,
    writes: u64 = 0,
};

const EXPECTED_MMIO = [_]MmioExpected{
    .{ .address = 0xff00, .reads = 400, .writes = 75 },
    .{ .address = 0xff04, .reads = 50 },
    .{ .address = 0xff10, .writes = 2 },
    .{ .address = 0xff12, .writes = 2 },
    .{ .address = 0xff13, .writes = 3 },
    .{ .address = 0xff14, .writes = 2 },
    .{ .address = 0xff16, .writes = 5 },
    .{ .address = 0xff17, .writes = 6 },
    .{ .address = 0xff18, .writes = 5 },
    .{ .address = 0xff19, .writes = 6 },
    .{ .address = 0xff1a, .writes = 13 },
    .{ .address = 0xff1b, .writes = 5 },
    .{ .address = 0xff1c, .writes = 6 },
    .{ .address = 0xff1d, .writes = 24 },
    .{ .address = 0xff1e, .writes = 5 },
    .{ .address = 0xff21, .writes = 1 },
    .{ .address = 0xff23, .writes = 1 },
    .{ .address = 0xff24, .writes = 29 },
    .{ .address = 0xff25, .reads = 20, .writes = 12 },
    .{ .address = 0xff26, .writes = 1 },
    .{ .address = 0xff30, .writes = 5 },
    .{ .address = 0xff31, .writes = 5 },
    .{ .address = 0xff32, .writes = 5 },
    .{ .address = 0xff33, .writes = 5 },
    .{ .address = 0xff34, .writes = 5 },
    .{ .address = 0xff35, .writes = 5 },
    .{ .address = 0xff36, .writes = 5 },
    .{ .address = 0xff37, .writes = 5 },
    .{ .address = 0xff38, .writes = 5 },
    .{ .address = 0xff39, .writes = 5 },
    .{ .address = 0xff3a, .writes = 5 },
    .{ .address = 0xff3b, .writes = 5 },
    .{ .address = 0xff3c, .writes = 5 },
    .{ .address = 0xff3d, .writes = 5 },
    .{ .address = 0xff3e, .writes = 5 },
    .{ .address = 0xff3f, .writes = 5 },
    .{ .address = 0xff42, .writes = 25 },
    .{ .address = 0xff43, .writes = 25 },
    .{ .address = 0xff46, .writes = 25 },
    .{ .address = 0xff4a, .writes = 25 },
};

fn validateMmio(actual: [0x80]AccessCounts) AuditError!void {
    var expected = [_]AccessCounts{.{}} ** 0x80;
    for (EXPECTED_MMIO) |item| {
        const index = item.address - 0xff00;
        if (expected[index].total() != 0)
            return error.PokemonHardwareSurfaceDrift;
        expected[index] = .{ .reads = item.reads, .writes = item.writes };
    }
    if (!std.meta.eql(actual, expected))
        return error.PokemonHardwareSurfaceDrift;
}

fn validateBenchmarkReducedMmio(actual: [0x80]AccessCounts) AuditError!void {
    const expected = [_]MmioExpected{
        .{ .address = 0xff47, .writes = 3 },
        .{ .address = 0xff48, .writes = 11 },
        .{ .address = 0xff49, .writes = 9 },
        .{ .address = 0xff4b, .writes = 37 },
    };
    for (expected) |item| {
        const counts = actual[item.address - 0xff00];
        if (counts.reads != item.reads or counts.writes != item.writes)
            return error.PokemonHardwareSurfaceDrift;
    }
    for (actual, 0..) |counts, index| {
        if (counts.total() == 0) continue;
        const address: u16 = @intCast(0xff00 + index);
        if (mmioClass(address) == .generic_other)
            return error.PokemonHardwareSurfaceDrift;
    }
}

fn validateVram(actual: [0x2000]AccessCounts) AuditError!void {
    for (actual, 0..) |counts, offset| {
        const address = 0x8000 + offset;
        const expected_writes: u64 = if (address >= 0x8ff0 and
            address <= 0x8fff)
            1
        else if (address >= 0x9c00 and address <= 0x9dff and
            address & 0x1f <= 0x13)
            8
        else if (address >= 0x9e00 and address <= 0x9e33 and
            address & 0x1f <= 0x13)
            8
        else
            0;
        if (counts.reads != 0 or counts.writes != expected_writes)
            return error.PokemonHardwareSurfaceDrift;
    }
}

pub fn validatePositive(report: Report) AuditError!void {
    if (report.chunks == 0 or report.rows == 0 or report.mcycles == 0 or
        report.callbacks == 0 or report.all_cpu_accesses == 0 or
        report.mmio.touched_addresses == 0 or
        report.mmio.accesses.total() == 0 or
        report.dedicated_mmio.touched_addresses == 0 or
        report.dedicated_mmio.accesses.total() == 0 or
        report.apu.touched_addresses == 0 or
        report.apu.accesses.total() == 0 or
        report.wave.touched_addresses == 0 or
        report.wave.accesses.total() == 0 or
        report.apu_semantics.events == 0 or
        report.apu_semantics.matching_ff25_reads == 0 or
        report.apu_semantics.writes == 0 or
        report.apu_semantics.wave_bursts == 0 or
        report.vram.touched_addresses == 0 or
        report.vram.accesses.total() == 0 or
        report.ff46_writes == 0 or report.dma_source_bytes == 0 or
        report.finish_lookahead_rows == 0 or
        report.finish_lookahead_mcycles == 0)
    {
        return error.PokemonHardwareSurfaceDrift;
    }
}

fn validateTargetReport(report: Report) AuditError!void {
    var unsupported_cases = report.unsafe;
    unsupported_cases.render_register_write_outside_vblank = 0;
    unsupported_cases.ff46_write_outside_vblank = 0;
    if (report.chunks == 0 or report.rows == 0 or report.mcycles == 0 or
        report.callbacks == 0 or report.actions != 33 or
        report.all_cpu_accesses == 0 or report.mmio.accesses.total() == 0 or
        report.finish_lookahead_rows == 0 or
        report.finish_lookahead_mcycles == 0 or
        !report.unsupported_semantics.targetAdmissible() or
        !std.meta.eql(unsupported_cases, UnsafeCases{}) or
        report.generic_mmio.touched_addresses != 4 or
        report.generic_mmio.accesses.reads != 0 or
        report.generic_mmio.accesses.writes != 60 or
        report.oam.accesses.total() != 0)
    {
        return error.PokemonHardwareSurfaceDrift;
    }
    try validateCommonRelations(report);
    if (!std.meta.eql(report, BENCHMARK_EXPECTED))
        return error.PokemonHardwareSurfaceDrift;
}

fn validateCommonRelations(report: Report) AuditError!void {
    const classified_mmio = AccessCounts{
        .reads = report.dedicated_mmio.accesses.reads +
            report.generic_mmio.accesses.reads,
        .writes = report.dedicated_mmio.accesses.writes +
            report.generic_mmio.accesses.writes,
    };
    const blocked = report.unsafe.dma_source_bus_blocked +
        report.unsafe.dma_oam_blocked;
    const dma_bytes: u64 = @intCast(report.dma_source_bytes);
    const apu_semantics = report.apu_semantics;
    if (report.mmio.touched_addresses !=
        report.dedicated_mmio.touched_addresses +
            report.generic_mmio.touched_addresses or
        !std.meta.eql(report.mmio.accesses, classified_mmio) or
        report.all_cpu_accesses !=
            report.dma_allowed_cpu_accesses + blocked or
        report.unsupported_semantics
            .verifier_rejected_dma_source_accesses !=
            report.unsafe.dma_source_bus_blocked or
        report.unsupported_semantics
            .verifier_rejected_dma_oam_accesses !=
            report.unsafe.dma_oam_blocked or
        report.ff46_writes != report.ff46_c3_writes or
        dma_bytes != report.ff46_writes * runner.dma.OAM_LENGTH or
        report.vram.accesses.reads != 0 or
        report.vram.accesses.writes != report.vram_vblank_writes or
        report.ppu_dedicated.accesses.writes !=
            report.scy_writes + report.scx_writes + report.wy_writes or
        apu_semantics.events != report.apu.accesses.total() +
            report.wave.accesses.total() or
        apu_semantics.matching_ff25_reads != report.apu.accesses.reads or
        apu_semantics.writes != report.apu.accesses.writes +
            report.wave.accesses.writes or
        apu_semantics.wave_writes != report.wave.accesses.writes or
        apu_semantics.wave_writes != apu_semantics.wave_bursts * 16 or
        apu_semantics.wave_bursts != apu_semantics.ordered_wave_bursts or
        apu_semantics.wave_bursts !=
            apu_semantics.dac_off_six_mcycles_before or
        apu_semantics.wave_bursts != apu_semantics.inactive_wave_bursts or
        apu_semantics.unsupported_events != 0)
    {
        return error.PokemonHardwareSurfaceDrift;
    }
}

pub fn validateReport(report: Report) AuditError!void {
    try validatePositive(report);
    unsupported.validatePinned(report.unsupported_semantics) catch
        return error.PokemonHardwareSurfaceDrift;
    try validateCommonRelations(report);
    if (report.generic_mmio.touched_addresses != 0 or
        report.generic_mmio.accesses.total() != 0 or
        !std.meta.eql(report.dedicated_mmio, report.mmio) or
        report.apu_semantics.final_knowledge != .unknown_channel_and_wave)
    {
        return error.PokemonHardwareSurfaceDrift;
    }
    if (!std.meta.eql(report, EXPECTED))
        return error.PokemonHardwareSurfaceDrift;
}
