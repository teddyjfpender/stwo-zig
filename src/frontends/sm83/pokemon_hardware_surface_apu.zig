//! Exact CPU-visible APU event audit for the pinned Pokemon prefix.

const std = @import("std");
const runner = @import("runner/mod.zig");
const apu_mmio = @import("runner/apu_mmio.zig");

const Access = runner.cartridge_memory.Access;
const Action = runner.cartridge_memory.Action;

pub const FinalKnowledge = enum {
    fully_known,
    unknown_channel_status,
    unknown_wave_phase,
    unknown_channel_and_wave,
};

pub const Semantics = struct {
    events: u64 = 0,
    matching_ff25_reads: u64 = 0,
    writes: u64 = 0,
    wave_writes: u64 = 0,
    wave_bursts: u64 = 0,
    ordered_wave_bursts: u64 = 0,
    dac_off_six_mcycles_before: u64 = 0,
    inactive_wave_bursts: u64 = 0,
    unsupported_events: u64 = 0,
    final_knowledge: FinalKnowledge = .fully_known,
};

pub const Audit = struct {
    state: apu_mmio.State,
    last_dac_off_mcycle: ?u32 = null,
    wave_position: u5 = 0,

    pub fn init(state: apu_mmio.State) Audit {
        return .{ .state = state };
    }

    pub fn record(
        self: *Audit,
        report: *Semantics,
        access_value: Access,
        mcycle: u32,
    ) !void {
        if (!apu_mmio.isAddress(access_value.logical_address)) return;
        report.events += 1;
        if (self.wave_position != 0 and
            !(access_value.action == .write and
                access_value.logical_address >= apu_mmio.WAVE_START and
                access_value.logical_address <= apu_mmio.WAVE_END))
        {
            return reject(report);
        }

        switch (access_value.action) {
            .read => {
                const value = self.state.read(access_value.logical_address) catch
                    return reject(report);
                if (access_value.logical_address != 0xff25 or
                    value != access_value.value)
                {
                    return reject(report);
                }
                report.matching_ff25_reads += 1;
            },
            .write => {
                report.writes += 1;
                if (access_value.logical_address >= apu_mmio.WAVE_START and
                    access_value.logical_address <= apu_mmio.WAVE_END)
                {
                    try self.recordWave(report, access_value, mcycle);
                }
                self.state.write(
                    access_value.logical_address,
                    access_value.value,
                ) catch return reject(report);
                if (access_value.logical_address == 0xff1a and
                    access_value.value & 0x80 == 0)
                {
                    self.last_dac_off_mcycle = mcycle;
                }
            },
        }
    }

    fn recordWave(
        self: *Audit,
        report: *Semantics,
        access_value: Access,
        mcycle: u32,
    ) !void {
        report.wave_writes += 1;
        if (self.wave_position == 0) {
            report.wave_bursts += 1;
            if (access_value.logical_address != apu_mmio.WAVE_START)
                return reject(report);
            const disabled = self.last_dac_off_mcycle orelse
                return reject(report);
            if (mcycle -| disabled != 6) return reject(report);
            report.dac_off_six_mcycles_before += 1;
            if (switch (self.state.wave_access) {
                .inactive => true,
                else => false,
            }) {
                report.inactive_wave_bursts += 1;
            } else return reject(report);
        }
        if (access_value.logical_address !=
            apu_mmio.WAVE_START + self.wave_position)
        {
            return reject(report);
        }
        self.wave_position += 1;
        if (self.wave_position == 16) {
            self.wave_position = 0;
            self.last_dac_off_mcycle = null;
            report.ordered_wave_bursts += 1;
        }
    }

    pub fn finish(self: Audit, report: *Semantics) !void {
        if (self.wave_position != 0) return reject(report);
        const status_unknown = self.state.channel_status == null;
        const wave_unknown = switch (self.state.wave_access) {
            .unknown => true,
            else => false,
        };
        report.final_knowledge = if (status_unknown and wave_unknown)
            .unknown_channel_and_wave
        else if (status_unknown)
            .unknown_channel_status
        else if (wave_unknown)
            .unknown_wave_phase
        else
            .fully_known;
    }
};

fn reject(report: *Semantics) error{UnsupportedApuEvent} {
    report.unsupported_events += 1;
    return error.UnsupportedApuEvent;
}

test "Pokemon APU wave bursts reject timing and order mutations" {
    const initial = apu_mmio.State{
        .enabled = true,
        .channel_status = 0,
        .wave_access = .inactive,
    };
    var timing = Audit.init(initial);
    var timing_report = Semantics{};
    try timing.record(&timing_report, apuAccess(0xff1a, .write, 0), 100);
    try std.testing.expectError(
        error.UnsupportedApuEvent,
        timing.record(
            &timing_report,
            apuAccess(apu_mmio.WAVE_START, .write, 1),
            105,
        ),
    );

    var order = Audit.init(initial);
    var order_report = Semantics{};
    try order.record(&order_report, apuAccess(0xff1a, .write, 0), 100);
    try std.testing.expectError(
        error.UnsupportedApuEvent,
        order.record(
            &order_report,
            apuAccess(apu_mmio.WAVE_START + 1, .write, 1),
            106,
        ),
    );
}

fn apuAccess(address: u16, action: Action, value: u8) Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}
