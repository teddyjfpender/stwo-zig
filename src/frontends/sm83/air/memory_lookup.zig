//! Byte-memory consistency witness and LogUp relation for flat SM83 memory.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const memory_mod = @import("../memory.zig");
const runner = @import("../runner/mod.zig");

pub const N_DIFF_BITS: usize = 27;
pub const N_ACCESS_COLUMNS: usize = 3 + N_DIFF_BITS;
pub const N_MAIN_COLUMNS: usize = execution.N_BUS_CYCLES * N_ACCESS_COLUMNS;
pub const N_EXECUTION_SUMS: usize = execution.N_BUS_CYCLES;
pub const N_EXECUTION_COLUMNS: usize = 4 * N_EXECUTION_SUMS;
pub const N_BOUNDARY_COLUMNS: usize = 4;
pub const N_INTERACTION_COLUMNS: usize =
    N_EXECUTION_COLUMNS + N_BOUNDARY_COLUMNS;
pub const N_CONSTRAINTS: usize =
    execution.N_BUS_CYCLES * (N_DIFF_BITS + 5);

pub const Relation = struct {
    z: QM31,
    clock_coefficient: QM31,
    value_coefficient: QM31,

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relation {
        const values = try channel.drawSecureFelts(allocator, 3);
        defer allocator.free(values);
        return .{
            .z = values[0],
            .clock_coefficient = values[1],
            .value_coefficient = values[2],
        };
    }

    pub fn dummy() Relation {
        return .{
            .z = QM31.fromU32Unchecked(1, 2, 3, 4),
            .clock_coefficient = QM31.fromU32Unchecked(4, 3, 2, 1),
            .value_coefficient = QM31.fromU32Unchecked(2, 4, 1, 3),
        };
    }

    pub fn combine(
        self: Relation,
        address: QM31,
        clock: QM31,
        value: QM31,
    ) QM31 {
        return address
            .add(self.clock_coefficient.mul(clock))
            .add(self.value_coefficient.mul(value))
            .sub(self.z);
    }
};

pub const Access = struct {
    enabled: bool = false,
    address: u16 = 0,
    previous_clock: u32 = 0,
    previous_value: u8 = 0,
    clock: u32 = 0,
    next_value: u8 = 0,
};

pub fn AccessRow(comptime S: type) type {
    return struct {
        previous_clock: S,
        previous_value: S,
        // Kept explicit so each LogUp denominator stays affine in trace columns.
        next_value: S,
        difference_bits: [N_DIFF_BITS]S,
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        accesses: [execution.N_BUS_CYCLES]AccessRow(S),

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
            var accesses: [execution.N_BUS_CYCLES]AccessRow(S) = undefined;
            for (&accesses, 0..) |*access, cycle| {
                const offset = cycle * N_ACCESS_COLUMNS;
                access.* = .{
                    .previous_clock = values[offset],
                    .previous_value = values[offset + 1],
                    .next_value = values[offset + 2],
                    .difference_bits = values[offset + 3 ..][0..N_DIFF_BITS].*,
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
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(machine: execution.Row(S), row: Row(S)) Evaluation {
            const one = S.one();
            var out: [N_CONSTRAINTS]S = undefined;
            var index: usize = 0;
            for (machine.bus, row.accesses, 0..) |cycle, access, cycle_index| {
                const enabled = cycle.read.add(cycle.write).sub(cycle.program);
                var difference = S.zero();
                for (access.difference_bits, 0..) |bit_value, bit_index| {
                    out[index] = bit_value.mul(bit_value.sub(enabled));
                    index += 1;
                    difference = difference.add(
                        base(S, @as(u64, 1) << @intCast(bit_index)).mul(bit_value),
                    );
                }
                out[index] = one.sub(enabled).mul(access.previous_clock);
                index += 1;
                out[index] = one.sub(enabled).mul(access.previous_value);
                index += 1;
                const clock = machine.mcycle_before.add(base(S, cycle_index + 1));
                out[index] = enabled.mul(
                    clock.sub(access.previous_clock).sub(one).sub(difference),
                );
                index += 1;
                const data_read = cycle.read.sub(cycle.program);
                out[index] = data_read.mul(cycle.value.sub(access.previous_value));
                index += 1;
                out[index] = access.next_value.sub(
                    data_read.mul(access.previous_value)
                        .add(cycle.write.mul(cycle.value)),
                );
                index += 1;
            }
            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        fn base(comptime T: type, value: u64) T {
            return T.fromBase(M31.fromU64(value));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub const Witness = struct {
    main: [N_MAIN_COLUMNS][]M31,
    final_clocks: []M31,
    accesses: []Access,
    allocator: std.mem.Allocator,
    columns_owned: bool = true,
    accesses_owned: bool = true,

    pub fn disownColumns(self: *Witness) void {
        self.columns_owned = false;
    }

    pub fn takeAccesses(self: *Witness) []Access {
        self.accesses_owned = false;
        return self.accesses;
    }

    pub fn deinit(self: *Witness) void {
        if (self.columns_owned) {
            for (self.main) |column| self.allocator.free(column);
            self.allocator.free(self.final_clocks);
        }
        if (self.accesses_owned) self.allocator.free(self.accesses);
        self.* = undefined;
    }
};

pub fn generateWitness(
    allocator: std.mem.Allocator,
    steps: anytype,
    initial: memory_mod.Image,
    final: memory_mod.Image,
) !Witness {
    if (steps.len < 16 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    const log_size: u32 = @intCast(std.math.log2_int(usize, steps.len));
    var result = Witness{
        .main = undefined,
        .final_clocks = undefined,
        .accesses = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column| allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    result.final_clocks = try allocator.alloc(M31, memory_mod.SIZE);
    errdefer allocator.free(result.final_clocks);
    @memset(result.final_clocks, M31.zero());
    result.accesses = try allocator.alloc(
        Access,
        steps.len * execution.N_BUS_CYCLES,
    );
    errdefer allocator.free(result.accesses);
    @memset(result.accesses, Access{});

    const memory = try allocator.dupe(u8, initial.bytes);
    defer allocator.free(memory);
    const clocks = try allocator.alloc(u32, memory_mod.SIZE);
    defer allocator.free(clocks);
    @memset(clocks, 0);

    var mcycle: u32 = 0;
    for (steps, 0..) |step, row| {
        const machine = stepColumns(step, mcycle);
        for (0..execution.N_BUS_CYCLES) |cycle_index| {
            const bus_offset = 2 * execution.N_STATE_COLUMNS +
                cycle_index * execution.N_BUS_COLUMNS;
            const active = machine[bus_offset + 2].toU32();
            const read = machine[bus_offset + 3].toU32();
            const write = machine[bus_offset + 4].toU32();
            const program = machine[bus_offset + 5].toU32();
            if (active > 1 or read > 1 or write > 1 or program > 1 or
                read + write > 1 or read > active or write > active or
                program > read)
                return error.InvalidMemoryAccess;
            if (read + write - program == 0) continue;
            const address_value = machine[bus_offset].toU32();
            const byte_value = machine[bus_offset + 1].toU32();
            if (address_value > std.math.maxInt(u16) or
                byte_value > std.math.maxInt(u8))
                return error.InvalidMemoryAccess;
            const address: u16 = @intCast(address_value);
            const value: u8 = @intCast(byte_value);
            const clock = std.math.add(
                u32,
                mcycle,
                @as(u32, @intCast(cycle_index)) + 1,
            ) catch return error.MemoryClockOverflow;
            const previous_clock = clocks[address];
            if (previous_clock >= clock) return error.InvalidMemoryClock;
            const previous_value = memory[address];
            if (read == 1 and value != previous_value)
                return error.MemoryReadMismatch;
            const difference = clock - previous_clock - 1;
            if (difference >= (@as(u32, 1) << N_DIFF_BITS))
                return error.MemoryClockDifferenceTooLarge;
            const next_value = if (write == 1)
                value
            else
                previous_value;
            if (write == 1) memory[address] = value;
            clocks[address] = clock;

            result.accesses[row * execution.N_BUS_CYCLES + cycle_index] = .{
                .enabled = true,
                .address = address,
                .previous_clock = previous_clock,
                .previous_value = previous_value,
                .clock = clock,
                .next_value = next_value,
            };
            const storage = try core_air_utils.circleBitReversedIndex(log_size, row);
            const offset = cycle_index * N_ACCESS_COLUMNS;
            result.main[offset][storage] = M31.fromCanonical(previous_clock);
            result.main[offset + 1][storage] = M31.fromCanonical(previous_value);
            result.main[offset + 2][storage] = M31.fromCanonical(next_value);
            for (0..N_DIFF_BITS) |bit_index| {
                result.main[offset + 3 + bit_index][storage] = M31.fromCanonical(
                    (difference >> @intCast(bit_index)) & 1,
                );
            }
        }
        mcycle = std.math.add(u32, mcycle, mCycles(step)) catch
            return error.MemoryClockOverflow;
    }
    if (!std.mem.eql(u8, memory, final.bytes)) return error.FinalMemoryMismatch;
    for (clocks, 0..) |clock, address| {
        result.final_clocks[
            try core_air_utils.circleBitReversedIndex(16, address)
        ] = M31.fromCanonical(clock);
    }
    return result;
}

fn stepColumns(step: anytype, mcycle: u32) [execution.N_MAIN_COLUMNS]M31 {
    if (@TypeOf(step) == runner.StepTrace)
        return execution.columns(step, mcycle);
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.executionColumns(step, mcycle);
    @compileError("unsupported SM83 proof input");
}

fn mCycles(step: anytype) u3 {
    if (@TypeOf(step) == runner.StepTrace) return step.cycle_count;
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.mCycles(step);
    @compileError("unsupported SM83 proof input");
}

pub fn evaluate(
    machine_values: [execution.N_MAIN_COLUMNS]M31,
    main_values: [N_MAIN_COLUMNS]M31,
) !Shipped.Evaluation {
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    var main: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine, machine_values) |*value, source| value.* = QM31.fromBase(source);
    for (&main, main_values) |*value, source| value.* = QM31.fromBase(source);
    return Shipped.evaluate(
        try execution.Row(QM31).fromColumns(&machine),
        try Row(QM31).fromColumns(&main),
    );
}

pub const RowPair = struct {
    n1: QM31,
    d1: QM31,
    n2: QM31,
    d2: QM31,
};

pub const Claims = struct {
    execution: [N_EXECUTION_SUMS]QM31,
    boundary: QM31,

    pub fn total(self: Claims) QM31 {
        var result = self.boundary;
        for (self.execution) |claim| result = result.add(claim);
        return result;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Interaction) void {
        self.owned = false;
    }

    pub fn deinit(self: *Interaction) void {
        if (self.owned) for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn executionPairs(
    machine: execution.Row(QM31),
    main: Row(QM31),
    relation: Relation,
) [N_EXECUTION_SUMS]RowPair {
    var accesses: [execution.N_BUS_CYCLES]RowPair = undefined;
    for (&accesses, machine.bus, main.accesses, 0..) |*pair, cycle, access, index| {
        const enabled = cycle.read.add(cycle.write).sub(cycle.program);
        const clock = machine.mcycle_before.add(q(index + 1));
        pair.* = .{
            .n1 = enabled.neg(),
            .d1 = relation.combine(cycle.address, access.previous_clock, access.previous_value),
            .n2 = enabled,
            .d2 = relation.combine(cycle.address, clock, access.next_value),
        };
    }
    return accesses;
}

pub fn boundaryPair(
    address: QM31,
    initial_value: QM31,
    final_clock: QM31,
    final_value: QM31,
    relation: Relation,
) RowPair {
    return .{
        .n1 = QM31.one(),
        .d1 = relation.combine(address, QM31.zero(), initial_value),
        .n2 = QM31.one().neg(),
        .d2 = relation.combine(address, final_clock, final_value),
    };
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

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    accesses: []const Access,
    execution_log_size: u32,
    initial: memory_mod.Image,
    final: memory_mod.Image,
    relation: Relation,
) !Interaction {
    const execution_size = @as(usize, 1) << @intCast(execution_log_size);
    if (accesses.len != execution_size * execution.N_BUS_CYCLES)
        return error.InvalidTraceLength;
    const final_clocks = try allocator.alloc(u32, memory_mod.SIZE);
    defer allocator.free(final_clocks);
    @memset(final_clocks, 0);
    for (accesses) |access| {
        if (access.enabled) final_clocks[access.address] = access.clock;
    }
    var columns: [N_INTERACTION_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (columns[0..N_EXECUTION_COLUMNS]) |*column| {
        column.* = try allocator.alloc(M31, execution_size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (columns[N_EXECUTION_COLUMNS..]) |*column| {
        column.* = try allocator.alloc(M31, memory_mod.SIZE);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var execution_claims: [N_EXECUTION_SUMS]QM31 = undefined;
    for (0..N_EXECUTION_SUMS) |sum_index| {
        var accumulator = QM31.zero();
        for (0..execution_size) |row| {
            accumulator = try accumulate(
                accumulator,
                accessPair(
                    accesses[row * execution.N_BUS_CYCLES + sum_index],
                    relation,
                ),
            );
            writeSecure(
                columns[4 * sum_index ..][0..4],
                try core_air_utils.circleBitReversedIndex(execution_log_size, row),
                accumulator,
            );
        }
        execution_claims[sum_index] = accumulator;
    }

    var boundary_claim = QM31.zero();
    for (0..memory_mod.SIZE) |address| {
        const storage = try core_air_utils.circleBitReversedIndex(16, address);
        boundary_claim = try accumulate(
            boundary_claim,
            boundaryPair(
                q(address),
                q(initial.bytes[address]),
                q(final_clocks[address]),
                q(final.bytes[address]),
                relation,
            ),
        );
        writeSecure(
            columns[N_EXECUTION_COLUMNS..][0..4],
            storage,
            boundary_claim,
        );
    }
    return .{
        .columns = columns,
        .claims = .{ .execution = execution_claims, .boundary = boundary_claim },
        .allocator = allocator,
    };
}

pub fn verifyCancellation(claims: Claims) !void {
    if (!claims.total().isZero()) return error.MemoryLookupSumNonZero;
}

fn accessPair(access: Access, relation: Relation) RowPair {
    if (!access.enabled) return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
    return .{
        .n1 = QM31.one().neg(),
        .d1 = relation.combine(
            q(access.address),
            q(access.previous_clock),
            q(access.previous_value),
        ),
        .n2 = QM31.one(),
        .d2 = relation.combine(
            q(access.address),
            q(access.clock),
            q(access.next_value),
        ),
    };
}

fn accumulate(current: QM31, pair: RowPair) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero()) return current;
    if (pair.d1.eql(pair.d2) and pair.n1.add(pair.n2).isZero()) return current;
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.MemoryLookupZeroDenominator));
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    const coordinates = value.toM31Array();
    for (columns, coordinates) |column, coordinate| column[row] = coordinate;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

test "memory lookup rejects forged reads, predecessor clocks, and inactive data" {
    var initial_bytes = [_]u8{0} ** memory_mod.SIZE;
    initial_bytes[0] = 0x86;
    initial_bytes[0x8000] = 2;
    var final_bytes = initial_bytes;
    const initial = try memory_mod.Image.init(&initial_bytes);
    const final = try memory_mod.Image.init(&final_bytes);
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memcpy(memory.bytes, &initial_bytes);
    var cpu = runner.Cpu{ .a = 1, .h = 0x80 };
    var steps: [16]runner.StepTrace = undefined;
    for (&steps) |*step| step.* = try runner.step(&cpu, &memory);

    var witness = try generateWitness(
        std.testing.allocator,
        &steps,
        initial,
        final,
    );
    defer witness.deinit();
    var mcycle: u32 = 0;
    for (steps, 0..) |step, row_index| {
        var row: [N_MAIN_COLUMNS]M31 = undefined;
        const storage = try core_air_utils.circleBitReversedIndex(4, row_index);
        for (&row, witness.main) |*value, column| value.* = column[storage];
        try std.testing.expect(
            (try evaluate(execution.columns(step, mcycle), row)).allZero(),
        );
        mcycle += step.cycle_count;
    }
    var interaction = try generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        initial,
        final,
        Relation.dummy(),
    );
    defer interaction.deinit();
    try verifyCancellation(interaction.claims);

    const access_index = for (witness.accesses, 0..) |access, index| {
        if (access.enabled) break index;
    } else unreachable;
    const access = witness.accesses[access_index];
    try std.testing.expectEqual(@as(u32, 2), access.clock);
    const cycle_index = access_index % execution.N_BUS_CYCLES;
    const offset = cycle_index * N_ACCESS_COLUMNS;
    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    var row: [N_MAIN_COLUMNS]M31 = undefined;
    for (&row, witness.main) |*value, column| value.* = column[storage];
    const machine = execution.columns(steps[0], 0);

    row[offset + 1] = M31.fromCanonical(access.previous_value + 1);
    try std.testing.expect(!(try evaluate(machine, row)).allZero());
    row[offset + 1] = M31.fromCanonical(access.previous_value);

    row[offset] = M31.one();
    @memset(row[offset + 3 ..][0..N_DIFF_BITS], M31.zero());
    try std.testing.expect((try evaluate(machine, row)).allZero());
    witness.accesses[access_index].previous_clock = 1;
    var forged_interaction = try generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        initial,
        final,
        Relation.dummy(),
    );
    defer forged_interaction.deinit();
    try std.testing.expectError(
        error.MemoryLookupSumNonZero,
        verifyCancellation(forged_interaction.claims),
    );

    const inactive_offset = (execution.N_BUS_CYCLES - 1) * N_ACCESS_COLUMNS;
    for (&row, witness.main) |*value, column| value.* = column[storage];
    row[inactive_offset] = M31.one();
    try std.testing.expect(!(try evaluate(machine, row)).allZero());
    row[inactive_offset] = M31.zero();
    row[inactive_offset + 3] = M31.one();
    try std.testing.expect(!(try evaluate(machine, row)).allZero());

    final_bytes[0x8000] = 3;
    try std.testing.expectError(
        error.FinalMemoryMismatch,
        generateWitness(
            std.testing.allocator,
            &steps,
            initial,
            try memory_mod.Image.init(&final_bytes),
        ),
    );
    final_bytes[0x8000] = 2;
    initial_bytes[0x8000] = 3;
    try std.testing.expectError(
        error.MemoryReadMismatch,
        generateWitness(
            std.testing.allocator,
            &steps,
            try memory_mod.Image.init(&initial_bytes),
            final,
        ),
    );
}

test "memory witness applies writes and rejects final-memory drift" {
    var initial_bytes = [_]u8{0} ** memory_mod.SIZE;
    initial_bytes[0] = 0x77;
    var final_bytes = initial_bytes;
    final_bytes[0x8000] = 5;
    const initial = try memory_mod.Image.init(&initial_bytes);
    const final = try memory_mod.Image.init(&final_bytes);
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memcpy(memory.bytes, &initial_bytes);
    var cpu = runner.Cpu{ .a = 5, .h = 0x80 };
    var steps: [16]runner.StepTrace = undefined;
    for (&steps) |*step| step.* = try runner.step(&cpu, &memory);

    var witness = try generateWitness(
        std.testing.allocator,
        &steps,
        initial,
        final,
    );
    defer witness.deinit();
    const write_index = for (witness.accesses, 0..) |access, index| {
        if (access.enabled and access.next_value != access.previous_value)
            break index;
    } else unreachable;
    const write = witness.accesses[write_index];
    try std.testing.expectEqual(@as(u8, 5), write.next_value);

    const cycle_index = write_index % execution.N_BUS_CYCLES;
    const offset = cycle_index * N_ACCESS_COLUMNS;
    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    var row: [N_MAIN_COLUMNS]M31 = undefined;
    for (&row, witness.main) |*value, column| value.* = column[storage];
    row[offset + 2] = M31.fromCanonical(4);
    try std.testing.expect(
        !(try evaluate(execution.columns(steps[0], 0), row)).allZero(),
    );
    row[offset + 2] = M31.fromCanonical(write.next_value);
    row[offset + 1] = M31.one();
    try std.testing.expect(
        (try evaluate(execution.columns(steps[0], 0), row)).allZero(),
    );
    witness.accesses[write_index].previous_value = 1;
    var forged_interaction = try generateInteraction(
        std.testing.allocator,
        witness.accesses,
        4,
        initial,
        final,
        Relation.dummy(),
    );
    defer forged_interaction.deinit();
    try std.testing.expectError(
        error.MemoryLookupSumNonZero,
        verifyCancellation(forged_interaction.claims),
    );

    final_bytes[0x8000] = 4;
    try std.testing.expectError(
        error.FinalMemoryMismatch,
        generateWitness(
            std.testing.allocator,
            &steps,
            initial,
            try memory_mod.Image.init(&final_bytes),
        ),
    );
}
