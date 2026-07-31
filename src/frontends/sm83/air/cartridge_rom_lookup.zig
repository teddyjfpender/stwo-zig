//! LogUp relation authenticating MBC3 ROM reads against a public 1 MiB table.
//!
//! Cartridge access semantics supply the physical offset. This relation binds
//! that offset and byte to the public ROM. SRAM ordering remains a separate
//! memory relation.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const cartridge = @import("../cartridge/mod.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const cartridge_machine_access = @import("cartridge_machine_access.zig");
const program_lookup = @import("program_lookup.zig");

const memory = runner.cartridge_memory;

pub const ROM_SIZE: usize = cartridge.header.ROM_SIZE;
pub const ROM_LOG_SIZE: u32 = 20;
pub const N_ACCESS_SLOTS: usize = 6;
pub const N_OFFSET_BITS: usize = 20;
pub const N_VALUE_BITS: usize = 8;
pub const N_ACCESS_COLUMNS: usize = 1 + N_OFFSET_BITS + N_VALUE_BITS;
pub const N_MAIN_COLUMNS: usize = N_ACCESS_SLOTS * N_ACCESS_COLUMNS;
pub const N_CONSTRAINTS: usize = N_MAIN_COLUMNS;
pub const N_SOURCE_COLUMNS: usize =
    N_ACCESS_SLOTS * cartridge_access.N_MAIN_COLUMNS;
pub const N_EXECUTION_SUMS: usize = 3;
pub const N_EXECUTION_COLUMNS: usize = 4 * N_EXECUTION_SUMS;
pub const N_ROM_COLUMNS: usize = 4;
pub const N_INTERACTION_COLUMNS: usize =
    N_EXECUTION_COLUMNS + N_ROM_COLUMNS;

comptime {
    std.debug.assert(ROM_SIZE == @as(usize, 1) << ROM_LOG_SIZE);
}

pub const Relation = program_lookup.Relation;
pub const RowPair = program_lookup.RowPair;

pub fn AccessRow(comptime S: type) type {
    return struct {
        active: S,
        offset_bits: [N_OFFSET_BITS]S,
        value_bits: [N_VALUE_BITS]S,

        pub fn offset(self: @This()) S {
            return compose(S, self.offset_bits);
        }

        pub fn value(self: @This()) S {
            return compose(S, self.value_bits);
        }
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        accesses: [N_ACCESS_SLOTS]AccessRow(S),

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidMainTraceShape;
            var accesses: [N_ACCESS_SLOTS]AccessRow(S) = undefined;
            for (&accesses, 0..) |*access, slot| {
                const offset = slot * N_ACCESS_COLUMNS;
                access.* = .{
                    .active = values[offset],
                    .offset_bits = values[offset + 1 ..][0..N_OFFSET_BITS].*,
                    .value_bits = values[offset + 1 + N_OFFSET_BITS ..][0..N_VALUE_BITS].*,
                };
            }
            return .{ .accesses = accesses };
        }
    };
}

pub fn Semantics(comptime S: type) type {
    return struct {
        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(row: Row(S)) Evaluation {
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            for (row.accesses) |access| {
                out[at] = bit(access.active);
                at += 1;
                for (access.offset_bits ++ access.value_bits) |value| {
                    out[at] = value.mul(value.sub(access.active));
                    at += 1;
                }
            }
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }
    };
}

pub const Claims = struct {
    execution: [N_EXECUTION_SUMS]QM31,
    rom: QM31,

    pub fn total(self: Claims) QM31 {
        var result = self.rom;
        for (self.execution) |claim| result = result.add(claim);
        return result;
    }
};

pub const Trace = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Trace) void {
        self.owned = false;
    }

    pub fn deinit(self: *Trace) void {
        if (self.owned) for (self.columns) |column|
            self.allocator.free(column);
        self.* = undefined;
    }
};

pub const PublicTable = struct {
    address: []M31,
    value: []M31,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PublicTable) void {
        self.allocator.free(self.address);
        self.allocator.free(self.value);
        self.* = undefined;
    }
};

pub fn generatePublicTable(
    allocator: std.mem.Allocator,
    rom: []const u8,
) !PublicTable {
    if (rom.len != ROM_SIZE) return error.InvalidRomSize;
    const address = try allocator.alloc(M31, ROM_SIZE);
    errdefer allocator.free(address);
    const value = try allocator.alloc(M31, ROM_SIZE);
    errdefer allocator.free(value);
    for (rom, 0..) |byte, offset| {
        const storage = try core_air_utils.circleBitReversedIndex(
            ROM_LOG_SIZE,
            offset,
        );
        address[storage] = M31.fromCanonical(@intCast(offset));
        value[storage] = M31.fromCanonical(byte);
    }
    return .{ .address = address, .value = value, .allocator = allocator };
}

pub fn generate(
    allocator: std.mem.Allocator,
    steps: anytype,
    rom: []const u8,
    relation: Relation,
) !Trace {
    if (rom.len != ROM_SIZE) return error.InvalidRomSize;
    if (steps.len == 0 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    const execution_log: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    const multiplicity = try multiplicities(allocator, steps, rom);
    defer allocator.free(multiplicity);

    var result = Trace{
        .columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column|
        allocator.free(column);
    for (result.columns[0..N_EXECUTION_COLUMNS]) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (result.columns[N_EXECUTION_COLUMNS..]) |*column| {
        column.* = try allocator.alloc(M31, ROM_SIZE);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var execution_claims: [N_EXECUTION_SUMS]QM31 = undefined;
    for (0..N_EXECUTION_SUMS) |sum_index| {
        var accumulator = QM31.zero();
        for (steps, 0..) |step, row_index| {
            const columns = try columnsFromStep(step);
            const row = try liftedRow(columns);
            accumulator = try accumulate(
                accumulator,
                executionPairs(row, relation)[sum_index],
            );
            writeSecure(
                result.columns[4 * sum_index ..][0..4],
                try core_air_utils.circleBitReversedIndex(
                    execution_log,
                    row_index,
                ),
                accumulator,
            );
        }
        execution_claims[sum_index] = accumulator;
    }

    var rom_claim = QM31.zero();
    for (rom, 0..) |byte, offset| {
        rom_claim = try accumulate(
            rom_claim,
            romPair(
                QM31.fromBase(M31.fromCanonical(@intCast(offset))),
                QM31.fromBase(M31.fromCanonical(byte)),
                QM31.fromBase(multiplicity[offset]),
                relation,
            ),
        );
        writeSecure(
            result.columns[N_EXECUTION_COLUMNS..][0..4],
            try core_air_utils.circleBitReversedIndex(
                ROM_LOG_SIZE,
                offset,
            ),
            rom_claim,
        );
    }
    result.claims = .{ .execution = execution_claims, .rom = rom_claim };
    return result;
}

pub fn columnsFromStep(
    trace: anytype,
) ![N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const T = @TypeOf(trace);
    if (T == runner.CartridgeStepTrace) {
        const validated = try cartridge_access.ValidatedStep.init(trace);
        for (validated.trace.activeAccesses(), 0..) |item, slot|
            try writeRomRead(&out, slot, item);
    } else if (T == machine.CartridgeStepResult) {
        const validated = try cartridge_machine_access.ValidatedStep.init(
            trace,
        );
        for (validated.activeCycles(), 0..) |cycle, slot|
            try writeRomRead(&out, slot, cycle.access);
    } else {
        @compileError("unsupported cartridge ROM lookup input");
    }
    return out;
}

pub fn rowFromAccessColumns(
    comptime S: type,
    values: []const S,
) !Row(S) {
    if (values.len != N_SOURCE_COLUMNS)
        return error.InvalidMainTraceShape;
    var result: [N_ACCESS_SLOTS]AccessRow(S) = undefined;
    for (&result, 0..) |*target, slot| {
        const offset = slot * cartridge_access.N_MAIN_COLUMNS;
        const source = try cartridge_access.Semantics(S).Row.fromColumns(
            values[offset..][0..cartridge_access.N_MAIN_COLUMNS],
        );
        target.* = .{
            .active = source.regions[
                @intFromEnum(memory.Region.cartridge_rom)
            ],
            .offset_bits = source.physical_offset,
            .value_bits = source.access_value,
        };
    }
    return .{ .accesses = result };
}

pub fn multiplicities(
    allocator: std.mem.Allocator,
    steps: anytype,
    rom: []const u8,
) ![]M31 {
    if (rom.len != ROM_SIZE) return error.InvalidRomSize;
    const output = try allocator.alloc(M31, ROM_SIZE);
    errdefer allocator.free(output);
    @memset(output, M31.zero());
    for (steps) |step| {
        const columns = try columnsFromStep(step);
        const row = try Row(M31).fromColumns(&columns);
        for (row.accesses) |access| {
            if (access.active.isZero()) continue;
            const offset = access.offset().toU32();
            const value = access.value().toU32();
            if (offset >= ROM_SIZE) return error.RomReadOutsideTable;
            if (value > std.math.maxInt(u8) or
                rom[offset] != @as(u8, @intCast(value)))
                return error.RomByteMismatch;
            output[offset] = output[offset].add(M31.one());
        }
    }
    return output;
}

pub fn committedMultiplicities(
    allocator: std.mem.Allocator,
    steps: anytype,
    rom: []const u8,
) ![]M31 {
    const counts = try multiplicities(allocator, steps, rom);
    defer allocator.free(counts);
    const output = try allocator.alloc(M31, ROM_SIZE);
    errdefer allocator.free(output);
    for (counts, 0..) |count, offset| {
        output[
            try core_air_utils.circleBitReversedIndex(
                ROM_LOG_SIZE,
                offset,
            )
        ] = count;
    }
    return output;
}

fn writeRomRead(
    out: *[N_MAIN_COLUMNS]M31,
    slot: usize,
    maybe_access: ?memory.Access,
) !void {
    const access = maybe_access orelse return;
    if (access.action != .read or access.region != .cartridge_rom)
        return;
    const physical_offset = access.physical_offset orelse
        return error.InvalidRomRead;
    const base = slot * N_ACCESS_COLUMNS;
    out[base] = M31.one();
    setBits(out[base + 1 ..][0..N_OFFSET_BITS], physical_offset);
    setBits(
        out[base + 1 + N_OFFSET_BITS ..][0..N_VALUE_BITS],
        access.value,
    );
}

pub fn executionPairs(
    row: Row(QM31),
    relation: Relation,
) [N_EXECUTION_SUMS]RowPair {
    var pairs: [N_EXECUTION_SUMS]RowPair = undefined;
    for (&pairs, 0..) |*pair, index| {
        const first = readPair(row.accesses[2 * index], relation);
        const second = readPair(row.accesses[2 * index + 1], relation);
        pair.* = .{
            .n1 = first.n1,
            .d1 = first.d1,
            .n2 = second.n1,
            .d2 = second.d1,
        };
    }
    return pairs;
}

pub fn romPair(
    offset: QM31,
    value: QM31,
    multiplicity: QM31,
    relation: Relation,
) RowPair {
    return .{
        .n1 = multiplicity,
        .d1 = relation.combine(offset, value),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

pub fn pairConstraint(
    current: QM31,
    previous: QM31,
    is_first: QM31,
    claim: QM31,
    pair: RowPair,
) QM31 {
    return program_lookup.pairConstraint(
        current,
        previous,
        is_first,
        claim,
        pair,
    );
}

pub fn verifyCancellation(claims: Claims) !void {
    if (!claims.total().isZero())
        return error.CartridgeRomLookupSumNonZero;
}

fn readPair(access: AccessRow(QM31), relation: Relation) RowPair {
    return .{
        .n1 = access.active.neg(),
        .d1 = relation.combine(access.offset(), access.value()),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

fn liftedRow(columns: [N_MAIN_COLUMNS]M31) !Row(QM31) {
    var values: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&values, columns) |*value, source|
        value.* = QM31.fromBase(source);
    return Row(QM31).fromColumns(&values);
}

fn accumulate(current: QM31, pair: RowPair) !QM31 {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.CartridgeRomLookupZeroDenominator));
}

fn compose(comptime S: type, bits: anytype) S {
    var result = S.zero();
    var power = S.one();
    for (bits) |value| {
        result = result.add(power.mul(value));
        power = power.add(power);
    }
    return result;
}

fn bit(value: anytype) @TypeOf(value) {
    return value.mul(value.sub(@TypeOf(value).one()));
}

fn setBits(out: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (out, 0..) |*column, index|
        column.* = M31.fromCanonical(@intCast((integer >> @intCast(index)) & 1));
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    const coordinates = value.toM31Array();
    for (columns, coordinates) |column, coordinate|
        column[row] = coordinate;
}

test "cartridge ROM lookup cancels fixed switched and duplicate reads" {
    const allocator = std.testing.allocator;
    const rom = try allocator.alloc(u8, ROM_SIZE);
    defer allocator.free(rom);
    @memset(rom, 0);
    rom[0x1234] = 0x11;
    rom[0x8123] = 0x22;
    var steps: [16]runner.CartridgeStepTrace = undefined;
    for (&steps, 0..) |*step, index|
        step.* = syntheticRead(index & 1 == 0);

    var trace = try generate(allocator, &steps, rom, Relation.dummy());
    defer trace.deinit();
    try verifyCancellation(trace.claims);
    const committed = try committedMultiplicities(allocator, &steps, rom);
    defer allocator.free(committed);
    for ([_]usize{ 0x1234, 0x8123 }) |offset| {
        try std.testing.expectEqual(
            M31.fromCanonical(8),
            committed[
                try core_air_utils.circleBitReversedIndex(
                    ROM_LOG_SIZE,
                    offset,
                )
            ],
        );
    }

    rom[0x8123] ^= 1;
    try std.testing.expectError(
        error.RomByteMismatch,
        multiplicities(allocator, &steps, rom),
    );
}

test "cartridge ROM public table fixes 20-bit boundary addresses" {
    const allocator = std.testing.allocator;
    const rom = try allocator.alloc(u8, ROM_SIZE);
    defer allocator.free(rom);
    @memset(rom, 0);
    rom[ROM_SIZE - 1] = 0xff;
    var table = try generatePublicTable(allocator, rom);
    defer table.deinit();
    const storage = try core_air_utils.circleBitReversedIndex(
        ROM_LOG_SIZE,
        ROM_SIZE - 1,
    );
    try std.testing.expectEqual(
        M31.fromCanonical(ROM_SIZE - 1),
        table.address[storage],
    );
    try std.testing.expectEqual(M31.fromCanonical(0xff), table.value[storage]);
}

fn syntheticRead(fixed: bool) runner.CartridgeStepTrace {
    const state = if (fixed)
        cartridge.mbc3.State{}
    else
        cartridge.mbc3.State{ .rom_bank_register = 2 };
    const address: u16 = if (fixed) 0x1234 else 0x4123;
    const offset: memory.PhysicalOffset = if (fixed) 0x1234 else 0x8123;
    const value: u8 = if (fixed) 0x11 else 0x22;
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.cycle_count = 1;
    trace.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = .read,
    };
    trace.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    trace.accesses[0] = .{
        .logical_address = address,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = offset,
        .mapper_before = state,
        .mapper_after = state,
        .value = value,
    };
    return trace;
}
