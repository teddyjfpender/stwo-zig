//! LogUp relation joining executed program reads to a committed 32 KiB ROM.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const rom_mod = @import("../rom.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const runner = @import("../runner/mod.zig");

pub const N_EXECUTION_SUMS: usize = 2;
pub const N_EXECUTION_COLUMNS: usize = 4 * N_EXECUTION_SUMS;
pub const N_ROM_COLUMNS: usize = 4;
pub const N_COLUMNS: usize = N_EXECUTION_COLUMNS + N_ROM_COLUMNS;

pub const Relation = struct {
    z: QM31,
    alpha: QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relation {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        return .{ .z = values[0], .alpha = values[1] };
    }

    pub fn dummy() Relation {
        return .{
            .z = QM31.fromU32Unchecked(1, 2, 3, 4),
            .alpha = QM31.fromU32Unchecked(4, 3, 2, 1),
        };
    }

    pub fn combine(self: Relation, address: QM31, value: QM31) QM31 {
        return address.add(self.alpha.mul(value)).sub(self.z);
    }
};

pub const RowPair = struct {
    n1: QM31,
    d1: QM31,
    n2: QM31,
    d2: QM31,

    fn single(numerator: QM31, denominator: QM31) RowPair {
        return .{
            .n1 = numerator,
            .d1 = denominator,
            .n2 = QM31.zero(),
            .d2 = QM31.one(),
        };
    }
};

pub const Claims = struct {
    execution: [N_EXECUTION_SUMS]QM31,
    rom: QM31,

    pub fn total(self: Claims) QM31 {
        return self.execution[0].add(self.execution[1]).add(self.rom);
    }
};

pub const Trace = struct {
    columns: [N_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Trace) void {
        self.owned = false;
    }

    pub fn deinit(self: *Trace) void {
        if (self.owned) for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    steps: anytype,
    rom: rom_mod.Rom,
    relation: Relation,
) !Trace {
    const execution_size = steps.len;
    if (execution_size == 0 or !std.math.isPowerOfTwo(execution_size))
        return error.InvalidTraceLength;
    const execution_log: u32 = @intCast(std.math.log2_int(usize, execution_size));
    const multiplicity = try multiplicities(allocator, steps, rom);
    defer allocator.free(multiplicity);

    var columns: [N_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (columns[0..N_EXECUTION_COLUMNS]) |*column| {
        column.* = try allocator.alloc(M31, execution_size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (columns[N_EXECUTION_COLUMNS..]) |*column| {
        column.* = try allocator.alloc(M31, rom_mod.SIZE);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var execution_claims: [N_EXECUTION_SUMS]QM31 = undefined;
    for (0..N_EXECUTION_SUMS) |sum_index| {
        var accumulator = QM31.zero();
        for (steps, 0..) |step, row| {
            const pair = executionPairsFromStep(step, relation)[sum_index];
            accumulator = try accumulate(accumulator, pair);
            writeSecure(
                columns[4 * sum_index ..][0..4],
                try core_air_utils.circleBitReversedIndex(execution_log, row),
                accumulator,
            );
        }
        execution_claims[sum_index] = accumulator;
    }

    var rom_claim = QM31.zero();
    for (0..rom_mod.SIZE) |address| {
        rom_claim = try accumulate(
            rom_claim,
            romPair(
                QM31.fromBase(M31.fromCanonical(@intCast(address))),
                QM31.fromBase(M31.fromCanonical(rom.bytes[address])),
                QM31.fromBase(multiplicity[address]),
                relation,
            ),
        );
        writeSecure(
            columns[N_EXECUTION_COLUMNS..][0..4],
            try core_air_utils.circleBitReversedIndex(rom_mod.LOG_SIZE, address),
            rom_claim,
        );
    }

    return .{
        .columns = columns,
        .claims = .{ .execution = execution_claims, .rom = rom_claim },
        .allocator = allocator,
    };
}

pub fn multiplicities(
    allocator: std.mem.Allocator,
    steps: anytype,
    rom: rom_mod.Rom,
) ![]M31 {
    const output = try allocator.alloc(M31, rom_mod.SIZE);
    errdefer allocator.free(output);
    @memset(output, M31.zero());
    for (steps) |step| {
        const machine = stepColumns(step, 0);
        var offset: usize = 2 * execution.N_STATE_COLUMNS;
        for (0..execution.N_BUS_CYCLES) |_| {
            const program = machine[offset + 5].toU32();
            if (program > 1) return error.InvalidProgramFetch;
            if (program == 1) {
                if (machine[offset + 2].toU32() != 1 or
                    machine[offset + 3].toU32() != 1 or
                    machine[offset + 4].toU32() != 0)
                    return error.InvalidProgramFetch;
                const address = machine[offset].toU32();
                const value = machine[offset + 1].toU32();
                if (address >= rom_mod.SIZE)
                    return error.ProgramFetchOutsideRom;
                if (value > std.math.maxInt(u8) or
                    rom.bytes[address] != @as(u8, @intCast(value)))
                    return error.ProgramByteMismatch;
                output[address] = output[address].add(M31.one());
            }
            offset += execution.N_BUS_COLUMNS;
        }
    }
    return output;
}

pub fn committedMultiplicities(
    allocator: std.mem.Allocator,
    steps: anytype,
    rom: rom_mod.Rom,
) ![]M31 {
    const counts = try multiplicities(allocator, steps, rom);
    defer allocator.free(counts);
    const output = try allocator.alloc(M31, rom_mod.SIZE);
    errdefer allocator.free(output);
    for (counts, 0..) |count, address| {
        output[
            try core_air_utils.circleBitReversedIndex(
                rom_mod.LOG_SIZE,
                address,
            )
        ] = count;
    }
    return output;
}

pub fn executionPairs(
    machine: execution.Row(QM31),
    relation: Relation,
) [N_EXECUTION_SUMS]RowPair {
    const first = fetchPair(machine.bus[0], relation);
    const second = fetchPair(machine.bus[1], relation);
    const third = fetchPair(machine.bus[2], relation);
    return .{
        .{
            .n1 = first.n1,
            .d1 = first.d1,
            .n2 = second.n1,
            .d2 = second.d1,
        },
        third,
    };
}

pub fn romPair(
    address: QM31,
    value: QM31,
    multiplicity: QM31,
    relation: Relation,
) RowPair {
    return RowPair.single(multiplicity, relation.combine(address, value));
}

pub fn pairConstraint(
    current: QM31,
    previous: QM31,
    is_first: QM31,
    claim: QM31,
    pair: RowPair,
) QM31 {
    const delta = current.sub(previous).add(is_first.mul(claim));
    return delta.mul(pair.d1).mul(pair.d2)
        .sub(pair.n1.mul(pair.d2))
        .sub(pair.n2.mul(pair.d1));
}

pub fn verifyCancellation(claims: Claims) !void {
    if (!claims.total().isZero()) return error.ProgramLookupSumNonZero;
}

fn executionPairsFromStep(
    step: anytype,
    relation: Relation,
) [N_EXECUTION_SUMS]RowPair {
    const machine_columns = stepColumns(step, 0);
    var lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, machine_columns) |*value, source| value.* = QM31.fromBase(source);
    return executionPairs(
        execution.Row(QM31).fromColumns(&lifted) catch unreachable,
        relation,
    );
}

fn stepColumns(step: anytype, mcycle: u32) [execution.N_MAIN_COLUMNS]M31 {
    if (@TypeOf(step) == runner.StepTrace)
        return execution.columns(step, mcycle);
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.executionColumns(step, mcycle);
    @compileError("unsupported SM83 proof input");
}

fn fetchPair(cycle: execution.Bus(QM31), relation: Relation) RowPair {
    return RowPair.single(
        cycle.program.neg(),
        relation.combine(cycle.address, cycle.value),
    );
}

fn accumulate(current: QM31, pair: RowPair) !QM31 {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.ProgramLookupZeroDenominator));
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    const coordinates = value.toM31Array();
    for (columns, coordinates) |column, coordinate| column[row] = coordinate;
}

test "program lookup cancels repeated ROM fetches and rejects byte drift" {
    var bytes = [_]u8{0} ** rom_mod.SIZE;
    bytes[0] = 0x80;
    bytes[1] = 0x80;
    const rom = try rom_mod.Rom.init(&bytes);
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memcpy(memory.bytes[0..rom_mod.SIZE], rom.bytes);
    var cpu = runner.Cpu{ .a = 1, .b = 2 };
    var steps: [16]runner.StepTrace = undefined;
    for (&steps) |*step| {
        step.* = try runner.step(&cpu, &memory);
        memory.write(cpu.pc, 0x80);
        bytes[cpu.pc] = 0x80;
    }
    const complete_rom = try rom_mod.Rom.init(&bytes);
    var trace = try generate(
        std.testing.allocator,
        &steps,
        complete_rom,
        Relation.dummy(),
    );
    defer trace.deinit();
    try verifyCancellation(trace.claims);
    const committed = try committedMultiplicities(
        std.testing.allocator,
        &steps,
        complete_rom,
    );
    defer std.testing.allocator.free(committed);
    for (0..16) |address| {
        try std.testing.expectEqual(
            M31.one(),
            committed[
                try core_air_utils.circleBitReversedIndex(
                    rom_mod.LOG_SIZE,
                    address,
                )
            ],
        );
    }

    bytes[0] = 0x81;
    try std.testing.expectError(
        error.ProgramByteMismatch,
        multiplicities(
            std.testing.allocator,
            &steps,
            try rom_mod.Rom.init(&bytes),
        ),
    );
}
