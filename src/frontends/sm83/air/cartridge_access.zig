//! RTC-free MBC3 access constraints; lookups authenticate contents and effects.
//! FF0F bus accesses fail closed pending a masked IF-MMIO relation.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const access_validation = @import("cartridge_access_validation.zig");
const mbc3 = cartridge.mbc3;
const memory = runner.cartridge_memory;
const N_BUS_ACTIONS: usize = 3;
const N_ACCESS_ACTIONS: usize = 2;
const N_REGIONS: usize = 11;
const BUS_ACTION_OFFSET: usize = 0;
const ACCESS_ACTION_OFFSET: usize = BUS_ACTION_OFFSET + N_BUS_ACTIONS;
pub const REGION_OFFSET: usize = ACCESS_ACTION_OFFSET + N_ACCESS_ACTIONS;
const BUS_ADDRESS_OFFSET: usize = REGION_OFFSET + N_REGIONS;
const LOGICAL_ADDRESS_OFFSET: usize = BUS_ADDRESS_OFFSET + 16;
const BUS_VALUE_OFFSET: usize = LOGICAL_ADDRESS_OFFSET + 16;
pub const ACCESS_VALUE_OFFSET: usize = BUS_VALUE_OFFSET + 8;
pub const PHYSICAL_OFFSET: usize = ACCESS_VALUE_OFFSET + 8;
const PHYSICAL_PRESENT_OFFSET: usize = PHYSICAL_OFFSET + 20;
pub const BEFORE_ROM_OFFSET: usize = PHYSICAL_PRESENT_OFFSET + 1;
const BEFORE_RAM_OFFSET: usize = BEFORE_ROM_OFFSET + 7;
const BEFORE_ENABLED_OFFSET: usize = BEFORE_RAM_OFFSET + 3;
pub const AFTER_ROM_OFFSET: usize = BEFORE_ENABLED_OFFSET + 1;
const AFTER_RAM_OFFSET: usize = AFTER_ROM_OFFSET + 7;
const AFTER_ENABLED_OFFSET: usize = AFTER_RAM_OFFSET + 3;
const ADDRESS_AUX_OFFSET: usize = AFTER_ENABLED_OFFSET + 1;
const N_ADDRESS_AUX: usize = 18;
const CONTROL_AUX_OFFSET: usize = ADDRESS_AUX_OFFSET + N_ADDRESS_AUX;
const N_CONTROL_AUX: usize = 3;
const ROM_ZERO_OFFSET: usize = CONTROL_AUX_OFFSET + N_CONTROL_AUX;
const ENABLE_MATCH_OFFSET: usize = ROM_ZERO_OFFSET + 1;
const IO_INVERSE_OFFSET: usize = ENABLE_MATCH_OFFSET + 1;
const ROM_INVERSE_OFFSET: usize = IO_INVERSE_OFFSET + 1;
const ENABLE_INVERSE_OFFSET: usize = ROM_INVERSE_OFFSET + 1;
const JOYPAD_INVERSE_OFFSET: usize = ENABLE_INVERSE_OFFSET + 1;
const TIMER_INVERSE_OFFSET: usize = JOYPAD_INVERSE_OFFSET + 1;
const PPU_BASE_INVERSE_OFFSET: usize = TIMER_INVERSE_OFFSET + 1;
const PPU_WY_INVERSE_OFFSET: usize = PPU_BASE_INVERSE_OFFSET + 1;
const IF_INVERSE_OFFSET: usize = PPU_WY_INVERSE_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = IF_INVERSE_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 381;
pub const N_CHAIN_CONSTRAINTS: usize = 11;
const JOYPAD_ADDRESS_MASK = access_validation.JOYPAD_ADDRESS_MASK;
const JOYPAD_ADDRESS_VALUE = access_validation.JOYPAD_ADDRESS_VALUE;
const TIMER_ADDRESS_MASK = access_validation.TIMER_ADDRESS_MASK;
const TIMER_ADDRESS_VALUE = access_validation.TIMER_ADDRESS_VALUE;
const PPU_BASE_ADDRESS_MASK = access_validation.PPU_BASE_ADDRESS_MASK;
const PPU_BASE_ADDRESS_VALUE = access_validation.PPU_BASE_ADDRESS_VALUE;
const PPU_WY_ADDRESS_MASK = access_validation.PPU_WY_ADDRESS_MASK;
const PPU_WY_ADDRESS_VALUE = access_validation.PPU_WY_ADDRESS_VALUE;
const IF_ADDRESS_MASK: u16 = 0xffff;
const IF_ADDRESS_VALUE: u16 = memory.INTERRUPT_FLAGS;
pub const ValidatedStep = struct {
    trace: runner.CartridgeStepTrace,
    mapper_before: [6]mbc3.State,
    mapper_after: [6]mbc3.State,
    pub fn init(
        trace: runner.CartridgeStepTrace,
    ) error{InvalidCartridgeAccess}!ValidatedStep {
        const count = trace.instruction.cycle_count;
        if (count == 0 or count > trace.accesses.len or
            trace.accesses[0] == null)
            return error.InvalidCartridgeAccess;

        var before = [_]mbc3.State{.{}} ** 6;
        var after = [_]mbc3.State{.{}} ** 6;
        var current = trace.accesses[0].?.mapper_before;
        for (0..count) |cycle_index| {
            const cycle = trace.instruction.cycles[cycle_index];
            if (trace.accesses[cycle_index]) |access| {
                if (cycle.action == .idle or
                    !std.meta.eql(access.mapper_before, current) or
                    !matchesCycle(access, cycle) or
                    !access_validation.isValid(access))
                    return error.InvalidCartridgeAccess;
                before[cycle_index] = access.mapper_before;
                after[cycle_index] = access.mapper_after;
                current = access.mapper_after;
            } else {
                if (cycle.action != .idle)
                    return error.InvalidCartridgeAccess;
                before[cycle_index] = current;
                after[cycle_index] = current;
            }
        }
        return .{
            .trace = trace,
            .mapper_before = before,
            .mapper_after = after,
        };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            bus_actions: [N_BUS_ACTIONS]S,
            access_actions: [N_ACCESS_ACTIONS]S,
            regions: [N_REGIONS]S,
            bus_address: [16]S,
            logical_address: [16]S,
            bus_value: [8]S,
            access_value: [8]S,
            physical_offset: [20]S,
            physical_present: S,
            before_rom: [7]S,
            before_ram: [3]S,
            before_enabled: S,
            after_rom: [7]S,
            after_ram: [3]S,
            after_enabled: S,
            address_aux: [N_ADDRESS_AUX]S,
            control_aux: [N_CONTROL_AUX]S,
            rom_zero: S,
            enable_match: S,
            inverses: [8]S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .bus_actions = values[BUS_ACTION_OFFSET..ACCESS_ACTION_OFFSET].*,
                    .access_actions = values[ACCESS_ACTION_OFFSET..REGION_OFFSET].*,
                    .regions = values[REGION_OFFSET..BUS_ADDRESS_OFFSET].*,
                    .bus_address = values[BUS_ADDRESS_OFFSET..LOGICAL_ADDRESS_OFFSET].*,
                    .logical_address = values[LOGICAL_ADDRESS_OFFSET..BUS_VALUE_OFFSET].*,
                    .bus_value = values[BUS_VALUE_OFFSET..ACCESS_VALUE_OFFSET].*,
                    .access_value = values[ACCESS_VALUE_OFFSET..PHYSICAL_OFFSET].*,
                    .physical_offset = values[PHYSICAL_OFFSET..PHYSICAL_PRESENT_OFFSET].*,
                    .physical_present = values[PHYSICAL_PRESENT_OFFSET],
                    .before_rom = values[BEFORE_ROM_OFFSET..BEFORE_RAM_OFFSET].*,
                    .before_ram = values[BEFORE_RAM_OFFSET..BEFORE_ENABLED_OFFSET].*,
                    .before_enabled = values[BEFORE_ENABLED_OFFSET],
                    .after_rom = values[AFTER_ROM_OFFSET..AFTER_RAM_OFFSET].*,
                    .after_ram = values[AFTER_RAM_OFFSET..AFTER_ENABLED_OFFSET].*,
                    .after_enabled = values[AFTER_ENABLED_OFFSET],
                    .address_aux = values[ADDRESS_AUX_OFFSET..CONTROL_AUX_OFFSET].*,
                    .control_aux = values[CONTROL_AUX_OFFSET..ROM_ZERO_OFFSET].*,
                    .rom_zero = values[ROM_ZERO_OFFSET],
                    .enable_match = values[ENABLE_MATCH_OFFSET],
                    .inverses = values[IO_INVERSE_OFFSET..N_MAIN_COLUMNS].*,
                };
            }
        };

        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub const ChainEvaluation = struct {
            values: [N_CHAIN_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(row: Row, is_active: S) Evaluation {
            @setEvalBranchQuota(100_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();

            out[at] = bit(is_active);
            at += 1;
            for (row.values[0..IO_INVERSE_OFFSET]) |value| {
                out[at] = bit(value);
                at += 1;
            }
            for (row.values) |value| {
                out[at] = one.sub(is_active).mul(value);
                at += 1;
            }

            const idle = busAction(row, .idle);
            const read = busAction(row, .read);
            const write = busAction(row, .write);
            const access_read = accessAction(row, .read);
            const access_write = accessAction(row, .write);
            const access_present = access_read.add(access_write);
            out[at] = idle.add(read).add(write).sub(is_active);
            at += 1;
            out[at] = access_read.sub(read);
            at += 1;
            out[at] = access_write.sub(write);
            at += 1;

            var selected_region = S.zero();
            for (row.regions) |selector|
                selected_region = selected_region.add(selector);
            out[at] = selected_region.sub(access_present);
            at += 1;
            for (row.logical_address, row.bus_address) |logical, bus| {
                out[at] = logical.sub(access_present.mul(bus));
                at += 1;
            }
            for (row.access_value, row.bus_value) |access, bus| {
                out[at] = access.sub(access_present.mul(bus));
                at += 1;
            }

            const b13 = row.logical_address[13];
            const b14 = row.logical_address[14];
            const b15 = row.logical_address[15];
            const fixed = row.address_aux[0];
            const switched = row.address_aux[1];
            const ram = row.address_aux[2];
            const upper = row.address_aux[3];
            const io_nibble = row.address_aux[4];
            const echo = row.address_aux[5];
            const unusable_low = row.address_aux[6];
            const bit_65_or = row.address_aux[7];
            const unusable_suffix = row.address_aux[8];
            const joypad_address = row.address_aux[9];
            const timer_address = row.address_aux[10];
            const ppu_address = row.address_aux[11];
            const ppu_base_address = row.address_aux[12];
            const ppu_wy_address = row.address_aux[13];
            const bit_54_or = row.address_aux[14];
            const ff_address = row.address_aux[15];
            const apu_suffix = row.address_aux[16];
            const apu_address = row.address_aux[17];
            const enable_control = row.control_aux[0];
            const rom_control = row.control_aux[1];
            const ram_control = row.control_aux[2];
            const io_mismatch = one.sub(row.logical_address[12])
                .add(one.sub(row.logical_address[11]))
                .add(one.sub(row.logical_address[10]))
                .add(one.sub(row.logical_address[9]));
            out[at] = fixed.sub(
                is_active.mul(one.sub(b15)).mul(one.sub(b14)),
            );
            at += 1;
            out[at] = switched.sub(one.sub(b15).mul(b14));
            at += 1;
            out[at] = ram.sub(b15.mul(one.sub(b14)).mul(b13));
            at += 1;
            out[at] = upper.sub(b15.mul(b14).mul(b13));
            at += 1;
            out[at] = io_nibble.mul(io_mismatch);
            at += 1;
            out[at] = is_active.mul(
                io_mismatch.mul(row.inverses[0])
                    .sub(one.sub(io_nibble)),
            );
            at += 1;
            out[at] = io_nibble.mul(row.inverses[0]);
            at += 1;
            out[at] = echo.sub(upper.mul(one.sub(io_nibble)));
            at += 1;
            out[at] = unusable_low.sub(
                one.sub(row.logical_address[8])
                    .mul(row.logical_address[7]),
            );
            at += 1;
            out[at] = bit_65_or.sub(
                row.logical_address[6]
                    .add(row.logical_address[5])
                    .sub(
                    row.logical_address[6].mul(
                        row.logical_address[5],
                    ),
                ),
            );
            at += 1;
            out[at] = unusable_suffix.sub(
                unusable_low.mul(bit_65_or),
            );
            at += 1;
            const device_matches = [_]S{
                joypad_address,
                timer_address,
            };
            const device_mismatches = [_]S{
                access_validation.addressMismatch(
                    S,
                    row.logical_address,
                    JOYPAD_ADDRESS_MASK,
                    JOYPAD_ADDRESS_VALUE,
                ),
                access_validation.addressMismatch(
                    S,
                    row.logical_address,
                    TIMER_ADDRESS_MASK,
                    TIMER_ADDRESS_VALUE,
                ),
            };
            for (
                device_matches,
                device_mismatches,
                row.inverses[3..5],
            ) |matches, mismatch, inverse| {
                out[at] = matches.mul(mismatch);
                at += 1;
                out[at] = is_active.mul(
                    mismatch.mul(inverse).sub(one.sub(matches)),
                );
                at += 1;
                out[at] = matches.mul(inverse);
                at += 1;
            }
            const ppu_matches = [_]S{
                ppu_base_address,
                ppu_wy_address,
            };
            const ppu_mismatches = [_]S{
                access_validation.addressMismatch(
                    S,
                    row.logical_address,
                    PPU_BASE_ADDRESS_MASK,
                    PPU_BASE_ADDRESS_VALUE,
                ),
                access_validation.addressMismatch(
                    S,
                    row.logical_address,
                    PPU_WY_ADDRESS_MASK,
                    PPU_WY_ADDRESS_VALUE,
                ),
            };
            for (
                ppu_matches,
                ppu_mismatches,
                row.inverses[5..7],
            ) |matches, mismatch, inverse| {
                out[at] = matches.mul(mismatch);
                at += 1;
                out[at] = is_active.mul(
                    mismatch.mul(inverse).sub(one.sub(matches)),
                );
                at += 1;
                out[at] = matches.mul(inverse);
                at += 1;
            }
            out[at] = ppu_address.sub(
                ppu_base_address.mul(
                    one.sub(row.logical_address[2].mul(
                        row.logical_address[1],
                    )),
                ).add(ppu_wy_address),
            );
            at += 1;
            out[at] = bit_54_or.sub(
                row.logical_address[5]
                    .add(row.logical_address[4])
                    .sub(
                    row.logical_address[5].mul(
                        row.logical_address[4],
                    ),
                ),
            );
            at += 1;
            out[at] = ff_address.sub(
                upper.mul(io_nibble).mul(row.logical_address[8]),
            );
            at += 1;
            out[at] = apu_suffix.sub(
                one.sub(row.logical_address[7])
                    .mul(one.sub(row.logical_address[6]))
                    .mul(bit_54_or),
            );
            at += 1;
            out[at] = apu_address.sub(ff_address.mul(apu_suffix));
            at += 1;
            const if_mismatch = access_validation.addressMismatch(
                S,
                row.logical_address,
                IF_ADDRESS_MASK,
                IF_ADDRESS_VALUE,
            );
            const if_inverse = row.inverses[7];
            out[at] = access_present.mul(
                if_mismatch.mul(if_inverse).sub(one),
            );
            at += 1;
            out[at] = is_active.sub(access_present).mul(if_inverse);
            at += 1;
            out[at] = enable_control.sub(
                write.mul(fixed).mul(one.sub(b13)),
            );
            at += 1;
            out[at] = rom_control.sub(write.mul(fixed).mul(b13));
            at += 1;
            out[at] = ram_control.sub(
                write.mul(switched).mul(one.sub(b13)),
            );
            at += 1;

            const system = one.sub(fixed).sub(switched).sub(ram).sub(echo);
            const enabled_ram = ram.mul(row.before_enabled);
            const disabled_ram = ram.mul(one.sub(row.before_enabled));
            const rom_read = read.mul(fixed.add(switched));
            const ram_access = access_present.mul(enabled_ram);
            const echo_access = access_present.mul(echo);

            const expected_regions = [_]S{
                rom_read,
                ram_access,
                write.mul(fixed.add(switched)),
                read.mul(disabled_ram),
                write.mul(disabled_ram),
                echo_access,
            };
            for (row.regions[0..expected_regions.len], expected_regions) |
                actual,
                expected,
            | {
                out[at] = actual.sub(expected);
                at += 1;
            }
            out[at] = row.regions[
                @intFromEnum(memory.Region.joypad_mmio)
            ].sub(access_present.mul(joypad_address));
            at += 1;
            out[at] = row.regions[
                @intFromEnum(memory.Region.timer_mmio)
            ].sub(access_present.mul(timer_address));
            at += 1;
            out[at] = row.regions[
                @intFromEnum(memory.Region.ppu_mmio)
            ].sub(access_present.mul(ppu_address));
            at += 1;
            out[at] = row.regions[
                @intFromEnum(memory.Region.apu_mmio)
            ].sub(access_present.mul(apu_address));
            at += 1;
            out[at] = row.regions[
                @intFromEnum(memory.Region.system)
            ].sub(access_present.mul(
                system.sub(joypad_address)
                    .sub(timer_address)
                    .sub(ppu_address)
                    .sub(apu_address),
            ));
            at += 1;

            out[at] = access_present
                .mul(upper.sub(echo))
                .mul(unusable_suffix);
            at += 1;
            const rom_region =
                row.regions[@intFromEnum(memory.Region.cartridge_rom)];
            const ram_region =
                row.regions[@intFromEnum(memory.Region.cartridge_ram)];
            const echo_region =
                row.regions[@intFromEnum(memory.Region.system_echo)];
            out[at] = row.physical_present
                .sub(rom_region.add(ram_region).add(echo_region));
            at += 1;
            var raw_bank = S.zero();
            var raw_power = one;
            for (row.before_rom) |value| {
                raw_bank = raw_bank.add(raw_power.mul(value));
                raw_power = raw_power.add(raw_power);
            }
            out[at] = row.rom_zero.mul(raw_bank);
            at += 1;
            out[at] = is_active.mul(
                raw_bank.mul(row.inverses[1])
                    .sub(one.sub(row.rom_zero)),
            );
            at += 1;
            out[at] = row.rom_zero.mul(row.inverses[1]);
            at += 1;
            const selected_rom = [_]S{
                row.before_rom[0].add(row.rom_zero),
                row.before_rom[1],
                row.before_rom[2],
                row.before_rom[3],
                row.before_rom[4],
                row.before_rom[5],
            };
            for (row.physical_offset, 0..) |actual, index| {
                const expected = if (index < 13)
                    row.physical_present.mul(row.logical_address[index])
                else if (index == 13)
                    rom_region.mul(row.logical_address[13])
                        .add(ram_region.mul(row.before_ram[0]))
                else if (index == 14)
                    read.mul(switched).mul(selected_rom[0])
                        .add(ram_region.mul(row.before_ram[1]))
                        .add(echo_region.mul(row.logical_address[14]))
                else if (index == 15)
                    read.mul(switched).mul(selected_rom[1])
                        .add(echo_region.mul(row.logical_address[15]))
                else
                    read.mul(switched).mul(selected_rom[index - 14]);
                out[at] = actual.sub(expected);
                at += 1;
            }

            const enable_mismatch = row.access_value[0]
                .add(one.sub(row.access_value[1]))
                .add(row.access_value[2])
                .add(one.sub(row.access_value[3]));
            out[at] = row.enable_match.mul(enable_mismatch);
            at += 1;
            out[at] = enable_control.mul(enable_mismatch)
                .mul(row.inverses[2])
                .sub(enable_control.sub(row.enable_match));
            at += 1;
            out[at] = one.sub(enable_control).mul(row.inverses[2]);
            at += 1;
            out[at] = row.enable_match.mul(row.inverses[2]);
            at += 1;
            for (row.after_rom, row.before_rom, row.access_value[0..7].*) |
                next,
                previous,
                value,
            | {
                out[at] = next.sub(
                    rom_control.mul(value)
                        .add(one.sub(rom_control).mul(previous)),
                );
                at += 1;
            }
            for (row.after_ram, row.before_ram, row.access_value[0..3].*) |
                next,
                previous,
                value,
            | {
                out[at] = next.sub(
                    ram_control.mul(value)
                        .add(one.sub(ram_control).mul(previous)),
                );
                at += 1;
            }
            out[at] = row.after_enabled.sub(
                row.enable_match.add(
                    one.sub(enable_control).mul(row.before_enabled),
                ),
            );
            at += 1;

            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        fn base(comptime T: type, value: u64) T {
            return T.fromBase(M31.fromU64(value));
        }

        pub fn evaluateChain(previous: Row, next: Row) ChainEvaluation {
            var out: [N_CHAIN_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            for (previous.after_rom, next.before_rom) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            for (previous.after_ram, next.before_ram) |after, before| {
                out[at] = after.sub(before);
                at += 1;
            }
            out[at] = previous.after_enabled.sub(next.before_enabled);
            at += 1;
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }
    };
}
pub fn columnsForCycle(
    step: ValidatedStep,
    cycle_index: usize,
) [N_MAIN_COLUMNS]M31 {
    std.debug.assert(cycle_index < step.trace.instruction.cycle_count);
    return columnsForBusCycle(
        step.trace.instruction.cycles[cycle_index],
        step.trace.accesses[cycle_index],
        step.mapper_before[cycle_index],
        step.mapper_after[cycle_index],
    );
}
pub fn columnsForBusCycle(
    cycle: runner.BusCycle,
    access: ?memory.Access,
    mapper_before: mbc3.State,
    mapper_after: mbc3.State,
) [N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[BUS_ACTION_OFFSET + @intFromEnum(cycle.action)] = M31.one();
    setBits(out[BUS_ADDRESS_OFFSET..LOGICAL_ADDRESS_OFFSET], cycle.address);
    setBits(out[BUS_VALUE_OFFSET..ACCESS_VALUE_OFFSET], cycle.value);
    if (access) |item| {
        out[ACCESS_ACTION_OFFSET + @intFromEnum(item.action)] = M31.one();
        out[REGION_OFFSET + @intFromEnum(item.region)] = M31.one();
        setBits(
            out[LOGICAL_ADDRESS_OFFSET..BUS_VALUE_OFFSET],
            item.logical_address,
        );
        setBits(
            out[ACCESS_VALUE_OFFSET..PHYSICAL_OFFSET],
            item.value,
        );
        if (item.physical_offset) |offset| {
            out[PHYSICAL_PRESENT_OFFSET] = M31.one();
            setBits(
                out[PHYSICAL_OFFSET..PHYSICAL_PRESENT_OFFSET],
                offset,
            );
        }
    }
    setMapper(
        &out,
        BEFORE_ROM_OFFSET,
        BEFORE_RAM_OFFSET,
        BEFORE_ENABLED_OFFSET,
        mapper_before,
    );
    setMapper(
        &out,
        AFTER_ROM_OFFSET,
        AFTER_RAM_OFFSET,
        AFTER_ENABLED_OFFSET,
        mapper_after,
    );
    setAuxiliaries(
        &out,
        if (access) |item| item.logical_address else 0,
        if (access) |item| item.value else 0,
        access != null,
        cycle.action == .write,
        mapper_before,
    );
    return out;
}
pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}
pub fn evaluate(
    columns: []const M31,
    is_active: M31,
) !Semantics(QM31).Evaluation {
    const row = try Semantics(M31).Row.fromColumns(columns);
    var values: [N_MAIN_COLUMNS]QM31 = undefined;
    for (row.values, 0..) |value, index|
        values[index] = QM31.fromBase(value);
    return Semantics(QM31).evaluate(
        try Semantics(QM31).Row.fromColumns(&values),
        QM31.fromBase(is_active),
    );
}

pub fn evaluateChain(
    previous: []const M31,
    next: []const M31,
) !Semantics(QM31).ChainEvaluation {
    if (previous.len != N_MAIN_COLUMNS or next.len != N_MAIN_COLUMNS)
        return error.InvalidMainTraceShape;
    var left: [N_MAIN_COLUMNS]QM31 = undefined;
    var right: [N_MAIN_COLUMNS]QM31 = undefined;
    for (previous, 0..) |value, index|
        left[index] = QM31.fromBase(value);
    for (next, 0..) |value, index|
        right[index] = QM31.fromBase(value);
    return Semantics(QM31).evaluateChain(
        try Semantics(QM31).Row.fromColumns(&left),
        try Semantics(QM31).Row.fromColumns(&right),
    );
}

fn matchesCycle(access: memory.Access, cycle: runner.BusCycle) bool {
    return access.logical_address == cycle.address and
        access.value == cycle.value and
        switch (cycle.action) {
            .idle => false,
            .read => access.action == .read,
            .write => access.action == .write,
        };
}

fn busAction(
    row: anytype,
    action: runner.BusAction,
) @TypeOf(row.bus_actions[0]) {
    return row.bus_actions[@intFromEnum(action)];
}

fn accessAction(
    row: anytype,
    action: memory.Action,
) @TypeOf(row.access_actions[0]) {
    return row.access_actions[@intFromEnum(action)];
}

fn bit(value: anytype) @TypeOf(value) {
    return value.mul(value.sub(@TypeOf(value).one()));
}

fn setMapper(
    out: *[N_MAIN_COLUMNS]M31,
    rom_offset: usize,
    ram_offset: usize,
    enabled_offset: usize,
    state: mbc3.State,
) void {
    setBits(out[rom_offset..ram_offset], state.rom_bank_register);
    setBits(out[ram_offset..enabled_offset], state.ram_bank_register);
    out[enabled_offset] = M31.fromCanonical(@intFromBool(state.ram_enabled));
}

fn setAuxiliaries(
    out: *[N_MAIN_COLUMNS]M31,
    address: u16,
    value: u8,
    access_present: bool,
    write: bool,
    mapper: mbc3.State,
) void {
    const b15 = address >> 15 & 1 == 1;
    const b14 = address >> 14 & 1 == 1;
    const b13 = address >> 13 & 1 == 1;
    const upper = b15 and b14 and b13;
    const io_nibble = address >> 9 & 0xf == 0xf;
    const fixed = !b15 and !b14;
    const switched = !b15 and b14;
    const ram = b15 and !b14 and b13;
    const low = address >> 8 & 1 == 0 and address >> 7 & 1 == 1;
    const bit_65_or = address >> 5 & 0x3 != 0;
    const address_aux = [_]bool{
        fixed,
        switched,
        ram,
        upper,
        io_nibble,
        upper and !io_nibble,
        low,
        bit_65_or,
        low and bit_65_or,
        access_validation.matchesAddress(
            address,
            JOYPAD_ADDRESS_MASK,
            JOYPAD_ADDRESS_VALUE,
        ),
        access_validation.matchesAddress(
            address,
            TIMER_ADDRESS_MASK,
            TIMER_ADDRESS_VALUE,
        ),
        access_validation.isPpuAddress(address),
        access_validation.matchesAddress(
            address,
            PPU_BASE_ADDRESS_MASK,
            PPU_BASE_ADDRESS_VALUE,
        ),
        access_validation.matchesAddress(
            address,
            PPU_WY_ADDRESS_MASK,
            PPU_WY_ADDRESS_VALUE,
        ),
        address >> 4 & 0x3 != 0,
        upper and io_nibble and address >> 8 & 1 == 1,
        address >> 7 & 1 == 0 and
            address >> 6 & 1 == 0 and
            address >> 4 & 0x3 != 0,
        access_validation.isApuAddress(address),
    };
    for (out[ADDRESS_AUX_OFFSET..CONTROL_AUX_OFFSET], address_aux) |
        *column,
        flag,
    | column.* = m31Bool(flag);

    const controls = [_]bool{
        write and fixed and !b13,
        write and fixed and b13,
        write and switched and !b13,
    };
    for (out[CONTROL_AUX_OFFSET..ROM_ZERO_OFFSET], controls) |
        *column,
        flag,
    | column.* = m31Bool(flag);

    const raw_bank: u32 = mapper.rom_bank_register;
    out[ROM_ZERO_OFFSET] = m31Bool(raw_bank == 0);
    const enable_mismatch: u32 = @popCount((value & 0xf) ^ 0xa);
    out[ENABLE_MATCH_OFFSET] =
        m31Bool(controls[0] and enable_mismatch == 0);
    const io_mismatch: u32 =
        @popCount((~@as(u32, address >> 9)) & 0xf);
    out[IO_INVERSE_OFFSET] =
        inverseOrZero(io_mismatch);
    out[ROM_INVERSE_OFFSET] = inverseOrZero(raw_bank);
    out[ENABLE_INVERSE_OFFSET] = if (controls[0])
        inverseOrZero(enable_mismatch)
    else
        M31.zero();
    out[JOYPAD_INVERSE_OFFSET] = inverseOrZero(access_validation.addressMismatchU16(
        address,
        JOYPAD_ADDRESS_MASK,
        JOYPAD_ADDRESS_VALUE,
    ));
    out[TIMER_INVERSE_OFFSET] = inverseOrZero(access_validation.addressMismatchU16(
        address,
        TIMER_ADDRESS_MASK,
        TIMER_ADDRESS_VALUE,
    ));
    out[PPU_BASE_INVERSE_OFFSET] = inverseOrZero(access_validation.addressMismatchU16(
        address,
        PPU_BASE_ADDRESS_MASK,
        PPU_BASE_ADDRESS_VALUE,
    ));
    out[PPU_WY_INVERSE_OFFSET] = inverseOrZero(access_validation.addressMismatchU16(
        address,
        PPU_WY_ADDRESS_MASK,
        PPU_WY_ADDRESS_VALUE,
    ));
    out[IF_INVERSE_OFFSET] = if (access_present)
        inverseOrZero(access_validation.addressMismatchU16(
            address,
            IF_ADDRESS_MASK,
            IF_ADDRESS_VALUE,
        ))
    else
        M31.zero();
}

fn inverseOrZero(value: u32) M31 {
    if (value == 0) return M31.zero();
    return M31.fromCanonical(value).invUncheckedNonZero();
}

fn m31Bool(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

fn setBits(out: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (out, 0..) |*column, index|
        column.* = M31.fromCanonical(@intCast((integer >> @intCast(index)) & 1));
}
