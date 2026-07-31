//! Semantic and adversarial controls for the cartridge-access leaf.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const subject = @import("cartridge_access.zig");

const mbc3 = cartridge.mbc3;
const memory = runner.cartridge_memory;
const ACCESS_ACTION_OFFSET = subject.REGION_OFFSET - 2;
const BUS_ADDRESS_OFFSET =
    subject.REGION_OFFSET + std.meta.fields(memory.Region).len;
const LOGICAL_ADDRESS_OFFSET = BUS_ADDRESS_OFFSET + 16;
const BUS_VALUE_OFFSET = subject.ACCESS_VALUE_OFFSET - 8;
const BEFORE_RAM_OFFSET = subject.BEFORE_ROM_OFFSET + 7;
const AFTER_RAM_OFFSET = subject.AFTER_ROM_OFFSET + 7;
const ADDRESS_AUX_OFFSET = subject.AFTER_ROM_OFFSET + 11;
const CONTROL_AUX_OFFSET = ADDRESS_AUX_OFFSET + 18;
const ROM_ZERO_OFFSET = CONTROL_AUX_OFFSET + 3;
const ENABLE_MATCH_OFFSET = ROM_ZERO_OFFSET + 1;
const IO_INVERSE_OFFSET = ENABLE_MATCH_OFFSET + 1;
const ROM_INVERSE_OFFSET = IO_INVERSE_OFFSET + 1;
const ENABLE_INVERSE_OFFSET = ROM_INVERSE_OFFSET + 1;
const JOYPAD_INVERSE_OFFSET = ENABLE_INVERSE_OFFSET + 1;
const TIMER_INVERSE_OFFSET = JOYPAD_INVERSE_OFFSET + 1;
const PPU_BASE_INVERSE_OFFSET = TIMER_INVERSE_OFFSET + 1;
const PPU_WY_INVERSE_OFFSET = PPU_BASE_INVERSE_OFFSET + 1;
const IF_INVERSE_OFFSET = subject.N_MAIN_COLUMNS - 1;

test "cartridge access leaf accepts honest address and mapper boundaries" {
    try std.testing.expectEqual(@as(usize, 138), subject.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 381), subject.N_CONSTRAINTS);
    const reset = mbc3.State{};
    const enabled = try mbc3.transition(reset, 0x1fff, 0xfa);
    const bank_64 = try mbc3.transition(reset, 0x3fff, 0x40);
    const bank_63 = try mbc3.transition(reset, 0x2000, 0x3f);
    const ram_7 = try mbc3.transition(enabled, 0x5fff, 7);
    const cases = [_]memory.Access{
        makeAccess(0x3fff, .read, .cartridge_rom, 0x3fff, reset, reset, 0x11),
        makeAccess(0x4000, .read, .cartridge_rom, 0x4000, reset, reset, 0x22),
        makeAccess(0x4000, .read, .cartridge_rom, 0, bank_64, bank_64, 0x33),
        makeAccess(0x7fff, .read, .cartridge_rom, 0xfffff, bank_63, bank_63, 0x44),
        makeAccess(0x1fff, .write, .mapper_control, null, reset, enabled, 0xfa),
        makeAccess(0x3fff, .write, .mapper_control, null, reset, bank_64, 0x40),
        makeAccess(0x5fff, .write, .mapper_control, null, enabled, ram_7, 7),
        makeAccess(0x7fff, .write, .mapper_control, null, bank_63, bank_63, 1),
        makeAccess(0xbfff, .write, .cartridge_ram, 0x7fff, ram_7, ram_7, 0x55),
        makeAccess(0xa000, .read, .cartridge_open_bus, null, reset, reset, 0x66),
        makeAccess(0xbfff, .write, .cartridge_ram_ignored, null, reset, reset, 0x77),
        makeAccess(0xe000, .read, .system_echo, 0xc000, reset, reset, 0x78),
        makeAccess(0xfdff, .write, .system_echo, 0xddff, reset, reset, 0x79),
        makeAccess(0xff10, .write, .apu_mmio, null, reset, reset, 0x80),
        makeAccess(0xff3f, .read, .apu_mmio, null, reset, reset, 0x81),
        makeAccess(0xff00, .read, .joypad_mmio, null, reset, reset, 0xcf),
        makeAccess(0xff04, .read, .timer_mmio, null, reset, reset, 0x12),
        makeAccess(0xff07, .write, .timer_mmio, null, reset, reset, 0x05),
        makeAccess(0xff40, .read, .ppu_mmio, null, reset, reset, 0x91),
        makeAccess(0xff41, .write, .ppu_mmio, null, reset, reset, 0x40),
        makeAccess(0xff42, .read, .ppu_mmio, null, reset, reset, 0x8d),
        makeAccess(0xff43, .write, .ppu_mmio, null, reset, reset, 0x8e),
        makeAccess(0xff44, .read, .ppu_mmio, null, reset, reset, 0x90),
        makeAccess(0xff45, .write, .ppu_mmio, null, reset, reset, 0x90),
        makeAccess(0xff4a, .write, .ppu_mmio, null, reset, reset, 0x4a),
        makeAccess(0x8000, .read, .system, null, reset, reset, 0x88),
        makeAccess(0xfe00, .read, .system, null, reset, reset, 0x89),
        makeAccess(0xff01, .read, .system, null, reset, reset, 0x8a),
        makeAccess(0xff03, .write, .system, null, reset, reset, 0x8b),
        makeAccess(0xff08, .read, .system, null, reset, reset, 0x8c),
        makeAccess(0xff46, .read, .system, null, reset, reset, 0x8f),
        makeAccess(0xff47, .write, .system, null, reset, reset, 0x90),
    };
    for (cases) |access| try expectHonest(access);
}

test "cartridge AIR quotients every type 0x13 RAM selector byte" {
    const enabled = try mbc3.transition(mbc3.State{}, 0, 0x0a);
    for (0..256) |raw_selector| {
        const value: u8 = @intCast(raw_selector);
        const selected = try mbc3.transition(enabled, 0x4000, value);
        const honest = try honestColumns(makeAccess(
            0x4000,
            .write,
            .mapper_control,
            null,
            enabled,
            selected,
            value,
        ));
        try std.testing.expect(
            (try subject.evaluate(&honest, M31.one())).allZero(),
        );

        for (0..3) |bit_index| {
            var forged_endpoint = honest;
            forged_endpoint[AFTER_RAM_OFFSET + bit_index] =
                flip(forged_endpoint[AFTER_RAM_OFFSET + bit_index]);
            try std.testing.expect(
                !(try subject.evaluate(
                    &forged_endpoint,
                    M31.one(),
                )).allZero(),
            );
        }

        const low_bit = raw_selector % 3;
        var stale_endpoint = honest;
        stale_endpoint[BUS_VALUE_OFFSET + low_bit] =
            flip(stale_endpoint[BUS_VALUE_OFFSET + low_bit]);
        stale_endpoint[subject.ACCESS_VALUE_OFFSET + low_bit] =
            flip(stale_endpoint[subject.ACCESS_VALUE_OFFSET + low_bit]);
        try std.testing.expect(
            !(try subject.evaluate(
                &stale_endpoint,
                M31.one(),
            )).allZero(),
        );

        for (3..8) |ignored_bit| {
            var equivalent_selector = honest;
            equivalent_selector[BUS_VALUE_OFFSET + ignored_bit] =
                flip(equivalent_selector[BUS_VALUE_OFFSET + ignored_bit]);
            equivalent_selector[subject.ACCESS_VALUE_OFFSET + ignored_bit] =
                flip(equivalent_selector[
                    subject.ACCESS_VALUE_OFFSET + ignored_bit
                ]);
            try std.testing.expect(
                (try subject.evaluate(
                    &equivalent_selector,
                    M31.one(),
                )).allZero(),
            );
        }
    }
}

test "FF0F bus accesses fail closed in the AIR" {
    const state = mbc3.State{};
    for ([_]memory.Action{ .read, .write }) |action| {
        const access = makeAccess(
            memory.INTERRUPT_FLAGS,
            action,
            .system,
            null,
            state,
            state,
            0x1f,
        );
        var trace = emptyTrace(1);
        setCycle(&trace, 0, access);
        const forbidden = subject.columnsForCycle(
            try subject.ValidatedStep.init(trace),
            0,
        );
        try std.testing.expect(
            !(try subject.evaluate(&forbidden, M31.one())).allZero(),
        );

        var relabeled = forbidden;
        relabeled[
            subject.REGION_OFFSET + @intFromEnum(memory.Region.system)
        ] = M31.zero();
        relabeled[
            subject.REGION_OFFSET + @intFromEnum(memory.Region.timer_mmio)
        ] = M31.one();
        try std.testing.expect(
            !(try subject.evaluate(&relabeled, M31.one())).allZero(),
        );

        var forged_inverse = try honestColumns(makeAccess(
            memory.INTERRUPT_FLAGS - 1,
            action,
            .system,
            null,
            state,
            state,
            0x1f,
        ));
        try std.testing.expect(
            (try subject.evaluate(&forged_inverse, M31.one())).allZero(),
        );
        forged_inverse[IF_INVERSE_OFFSET] = M31.zero();
        try std.testing.expect(
            !(try subject.evaluate(&forged_inverse, M31.one())).allZero(),
        );
    }
}

test "cartridge access device classifiers preserve the cubic degree bound" {
    const variables =
        [_]Degree{Degree.variable()} ** subject.N_MAIN_COLUMNS;
    const row = try subject.Semantics(Degree).Row.fromColumns(&variables);
    const evaluation = subject.Semantics(Degree).evaluate(
        row,
        Degree.variable(),
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(@as(u32, 3), maximum);
}

test "cartridge access leaf binds auxiliaries chains idle and vacuity" {
    const initial = mbc3.State{};
    const enabled = try mbc3.transition(initial, 0x1fff, 0x0a);
    const selected = try mbc3.transition(initial, 0x2000, 5);
    var trace = emptyTrace(3);
    setCycle(&trace, 0, makeAccess(
        0x2000,
        .write,
        .mapper_control,
        null,
        initial,
        selected,
        5,
    ));
    trace.instruction.cycles[1] = .{
        .address = 0x2000,
        .value = 5,
        .action = .idle,
    };
    setCycle(&trace, 2, makeAccess(
        0x4123,
        .read,
        .cartridge_rom,
        5 * 0x4000 + 0x123,
        selected,
        selected,
        5,
    ));
    const validated = try subject.ValidatedStep.init(trace);
    var rows: [3][subject.N_MAIN_COLUMNS]M31 = undefined;
    for (&rows, 0..) |*row, index| {
        row.* = subject.columnsForCycle(validated, index);
        try std.testing.expect((try subject.evaluate(row, M31.one())).allZero());
    }
    try std.testing.expectEqualDeep(
        rows[1],
        subject.columnsForBusCycle(
            trace.instruction.cycles[1],
            null,
            selected,
            selected,
        ),
    );
    try std.testing.expect(
        (try subject.evaluateChain(&rows[0], &rows[1])).allZero(),
    );
    try std.testing.expect(
        (try subject.evaluateChain(&rows[1], &rows[2])).allZero(),
    );

    const mutations = [_]usize{
        subject.PHYSICAL_OFFSET,
        subject.AFTER_ROM_OFFSET,
        subject.AFTER_ROM_OFFSET + 7,
        subject.AFTER_ROM_OFFSET + 10,
        subject.REGION_OFFSET + @intFromEnum(memory.Region.system),
        ACCESS_ACTION_OFFSET + @intFromEnum(memory.Action.write),
        LOGICAL_ADDRESS_OFFSET,
        subject.ACCESS_VALUE_OFFSET,
    };
    for (mutations) |column| {
        var forged = rows[2];
        forged[column] = flip(forged[column]);
        try std.testing.expect(
            !(try subject.evaluate(&forged, M31.one())).allZero(),
        );
    }

    const branch_rows = [_][subject.N_MAIN_COLUMNS]M31{
        try honestColumns(makeAccess(
            0x00a0,
            .read,
            .cartridge_rom,
            0x00a0,
            initial,
            initial,
            0x42,
        )),
        try honestColumns(makeAccess(
            0x4000,
            .read,
            .cartridge_rom,
            5 * 0x4000,
            selected,
            selected,
            0x43,
        )),
        try honestColumns(makeAccess(
            0xa000,
            .read,
            .cartridge_ram,
            0,
            enabled,
            enabled,
            0x44,
        )),
        try honestColumns(makeAccess(
            0xe000,
            .read,
            .system_echo,
            0xc000,
            initial,
            initial,
            0x45,
        )),
        try honestColumns(makeAccess(
            0xff00,
            .read,
            .joypad_mmio,
            null,
            initial,
            initial,
            0x46,
        )),
        try honestColumns(makeAccess(
            0xff04,
            .read,
            .timer_mmio,
            null,
            initial,
            initial,
            0x47,
        )),
        try honestColumns(makeAccess(
            0xff40,
            .read,
            .ppu_mmio,
            null,
            initial,
            initial,
            0x48,
        )),
        try honestColumns(makeAccess(
            0xff4a,
            .write,
            .ppu_mmio,
            null,
            initial,
            initial,
            0x49,
        )),
        try honestColumns(makeAccess(
            0xff10,
            .write,
            .apu_mmio,
            null,
            initial,
            initial,
            0x80,
        )),
        try honestColumns(makeAccess(
            0xff3f,
            .read,
            .apu_mmio,
            null,
            initial,
            initial,
            0x81,
        )),
        try honestColumns(makeAccess(
            0x0000,
            .write,
            .mapper_control,
            null,
            initial,
            try mbc3.transition(initial, 0x0000, 0x0a),
            0x0a,
        )),
        try honestColumns(makeAccess(
            0x0000,
            .write,
            .mapper_control,
            null,
            initial,
            try mbc3.transition(initial, 0x0000, 0x0b),
            0x0b,
        )),
        try honestColumns(makeAccess(
            0x2000,
            .write,
            .mapper_control,
            null,
            initial,
            selected,
            5,
        )),
        try honestColumns(makeAccess(
            0x4000,
            .write,
            .mapper_control,
            null,
            enabled,
            try mbc3.transition(enabled, 0x4000, 2),
            2,
        )),
    };
    for (ADDRESS_AUX_OFFSET..CONTROL_AUX_OFFSET) |column|
        try expectBothMutationBranches(&branch_rows, column);
    for (CONTROL_AUX_OFFSET..PPU_WY_INVERSE_OFFSET + 1) |column|
        try expectBothMutationBranches(&branch_rows, column);

    var broken_chain = rows[2];
    broken_chain[subject.BEFORE_ROM_OFFSET] =
        flip(broken_chain[subject.BEFORE_ROM_OFFSET]);
    try std.testing.expect(
        !(try subject.evaluateChain(&rows[1], &broken_chain)).allZero(),
    );
    var vacuous = subject.inactiveColumns();
    try std.testing.expect(
        (try subject.evaluate(&vacuous, M31.zero())).allZero(),
    );
    vacuous[BUS_VALUE_OFFSET] = M31.one();
    try std.testing.expect(
        !(try subject.evaluate(&vacuous, M31.zero())).allZero(),
    );

    var forged_ppu = try honestColumns(makeAccess(
        0xff40,
        .read,
        .ppu_mmio,
        null,
        initial,
        initial,
        0x91,
    ));
    forged_ppu[BUS_ADDRESS_OFFSET + 1] = M31.one();
    forged_ppu[LOGICAL_ADDRESS_OFFSET + 1] = M31.one();
    try std.testing.expect(
        !(try subject.evaluate(&forged_ppu, M31.one())).allZero(),
    );
}

test "device addresses cannot be relabeled as generic system memory" {
    const state = mbc3.State{};
    const cases = [_]struct {
        address: u16,
        region: memory.Region,
    }{
        .{ .address = 0xff00, .region = .joypad_mmio },
        .{ .address = 0xff04, .region = .timer_mmio },
        .{ .address = 0xff05, .region = .timer_mmio },
        .{ .address = 0xff06, .region = .timer_mmio },
        .{ .address = 0xff07, .region = .timer_mmio },
        .{ .address = 0xff40, .region = .ppu_mmio },
        .{ .address = 0xff41, .region = .ppu_mmio },
        .{ .address = 0xff42, .region = .ppu_mmio },
        .{ .address = 0xff43, .region = .ppu_mmio },
        .{ .address = 0xff44, .region = .ppu_mmio },
        .{ .address = 0xff45, .region = .ppu_mmio },
        .{ .address = 0xff4a, .region = .ppu_mmio },
    };
    for (cases) |case| {
        const honest = try honestColumns(makeAccess(
            case.address,
            .read,
            case.region,
            null,
            state,
            state,
            0xa5,
        ));
        var relabeled = honest;
        relabeled[
            subject.REGION_OFFSET + @intFromEnum(case.region)
        ] = M31.zero();
        relabeled[
            subject.REGION_OFFSET + @intFromEnum(memory.Region.system)
        ] = M31.one();
        try std.testing.expect(
            !(try subject.evaluate(&relabeled, M31.one())).allZero(),
        );

        var trace = emptyTrace(1);
        setCycle(&trace, 0, makeAccess(
            case.address,
            .read,
            .system,
            null,
            state,
            state,
            0xa5,
        ));
        try std.testing.expectError(
            error.InvalidCartridgeAccess,
            subject.ValidatedStep.init(trace),
        );
    }
}

test "ordinary system addresses cannot be relabeled as devices" {
    const state = mbc3.State{};
    const cases = [_]struct {
        address: u16,
        forged_region: memory.Region,
    }{
        .{ .address = 0xfe00, .forged_region = .joypad_mmio },
        .{ .address = 0xff01, .forged_region = .joypad_mmio },
        .{ .address = 0xff03, .forged_region = .timer_mmio },
        .{ .address = 0xff08, .forged_region = .timer_mmio },
        .{ .address = 0xff46, .forged_region = .ppu_mmio },
        .{ .address = 0xff47, .forged_region = .ppu_mmio },
        .{ .address = 0xff4b, .forged_region = .ppu_mmio },
    };
    for (cases) |case| {
        const honest = try honestColumns(makeAccess(
            case.address,
            .write,
            .system,
            null,
            state,
            state,
            0x5a,
        ));
        var relabeled = honest;
        relabeled[
            subject.REGION_OFFSET + @intFromEnum(memory.Region.system)
        ] = M31.zero();
        relabeled[
            subject.REGION_OFFSET + @intFromEnum(case.forged_region)
        ] = M31.one();
        try std.testing.expect(
            !(try subject.evaluate(&relabeled, M31.one())).allZero(),
        );
    }
}

test "cartridge access validation rejects forged metadata and chain gaps" {
    const initial = mbc3.State{};
    const selected = try mbc3.transition(initial, 0x2000, 2);
    var trace = emptyTrace(2);
    setCycle(&trace, 0, makeAccess(
        0x2000,
        .write,
        .mapper_control,
        null,
        initial,
        selected,
        2,
    ));
    setCycle(&trace, 1, makeAccess(
        0x4000,
        .read,
        .cartridge_rom,
        0x8000,
        initial,
        initial,
        2,
    ));
    try std.testing.expectError(
        error.InvalidCartridgeAccess,
        subject.ValidatedStep.init(trace),
    );
    trace.accesses[1].?.mapper_before = selected;
    trace.accesses[1].?.mapper_after = selected;
    trace.accesses[1].?.physical_offset = 0x8001;
    try std.testing.expectError(
        error.InvalidCartridgeAccess,
        subject.ValidatedStep.init(trace),
    );
    trace.instruction.cycle_count = 7;
    try std.testing.expectError(
        error.InvalidCartridgeAccess,
        subject.ValidatedStep.init(trace),
    );

    var invalid_ppu = emptyTrace(1);
    setCycle(&invalid_ppu, 0, makeAccess(
        0xff4b,
        .read,
        .ppu_mmio,
        null,
        initial,
        initial,
        0,
    ));
    try std.testing.expectError(
        error.InvalidCartridgeAccess,
        subject.ValidatedStep.init(invalid_ppu),
    );
}

fn honestColumns(
    access: memory.Access,
) ![subject.N_MAIN_COLUMNS]M31 {
    var trace = emptyTrace(1);
    setCycle(&trace, 0, access);
    return subject.columnsForCycle(
        try subject.ValidatedStep.init(trace),
        0,
    );
}

fn expectHonest(access: memory.Access) !void {
    const columns = try honestColumns(access);
    try std.testing.expect(
        (try subject.evaluate(&columns, M31.one())).allZero(),
    );
}

fn emptyTrace(cycle_count: u3) runner.CartridgeStepTrace {
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.cycle_count = cycle_count;
    trace.accesses = [_]?memory.Access{null} ** 6;
    return trace;
}

fn setCycle(
    trace: *runner.CartridgeStepTrace,
    index: usize,
    access: memory.Access,
) void {
    trace.instruction.cycles[index] = .{
        .address = access.logical_address,
        .value = access.value,
        .action = switch (access.action) {
            .read => .read,
            .write => .write,
        },
    };
    trace.accesses[index] = access;
}

fn makeAccess(
    address: u16,
    action: memory.Action,
    region: memory.Region,
    physical_offset: ?memory.PhysicalOffset,
    before: mbc3.State,
    after: mbc3.State,
    value: u8,
) memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = physical_offset,
        .mapper_before = before,
        .mapper_after = after,
        .value = value,
    };
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
}

fn expectBothMutationBranches(
    rows: []const [subject.N_MAIN_COLUMNS]M31,
    column: usize,
) !void {
    var saw_zero = false;
    var saw_nonzero = false;
    for (rows) |row| {
        const is_zero = row[column].isZero();
        if ((is_zero and saw_zero) or (!is_zero and saw_nonzero)) continue;
        var forged = row;
        forged[column] = flip(forged[column]);
        try std.testing.expect(
            !(try subject.evaluate(&forged, M31.one())).allZero(),
        );
        if (is_zero)
            saw_zero = true
        else
            saw_nonzero = true;
    }
    try std.testing.expect(saw_zero);
    try std.testing.expect(saw_nonzero);
}

const Degree = struct {
    degree: u32,

    fn variable() Degree {
        return .{ .degree = 1 };
    }

    pub fn zero() Degree {
        return .{ .degree = 0 };
    }

    pub fn one() Degree {
        return .{ .degree = 0 };
    }

    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
