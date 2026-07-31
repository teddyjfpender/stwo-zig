//! Ordered mutable-memory lookup for RTC-free MBC3 execution.
//!
//! The key space is the 64 KiB system image followed by 32 KiB physical SRAM.
//! ROM, mapper control, open bus, ignored SRAM, and device MMIO skip this
//! relation; their own relations authenticate them.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const cartridge_mod = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const execution = @import("execution.zig");
pub const memory_clock = @import("cartridge_memory_clock.zig");
const image = @import("cartridge_memory_image.zig");

pub const SYSTEM_SIZE: usize = runner.cartridge_memory.SYSTEM_SIZE;
pub const SRAM_SIZE: usize = cartridge_mod.header.RAM_SIZE;
pub const SRAM_KEY_OFFSET: usize = SYSTEM_SIZE;
pub const KEY_COUNT: usize = SYSTEM_SIZE + SRAM_SIZE;
pub const BOUNDARY_LOG_SIZE: u32 = 17;
pub const BOUNDARY_SIZE: usize =
    @as(usize, 1) << @intCast(BOUNDARY_LOG_SIZE);
pub const N_DIFF_BITS: usize = 28;
pub const PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const PREVIOUS_VALUE_OFFSET: usize = 1;
pub const NEXT_VALUE_OFFSET: usize = 2;
pub const DIFFERENCE_BITS_OFFSET: usize = 3;
pub const PROJECTED_ENABLED_OFFSET: usize =
    DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const PROJECTED_READ_OFFSET: usize = PROJECTED_ENABLED_OFFSET + 1;
pub const PROJECTED_WRITE_OFFSET: usize = PROJECTED_READ_OFFSET + 1;
pub const PROJECTED_KEY_OFFSET: usize = PROJECTED_WRITE_OFFSET + 1;
pub const PROJECTED_VALUE_OFFSET: usize = PROJECTED_KEY_OFFSET + 1;
pub const N_ACCESS_COLUMNS: usize = PROJECTED_VALUE_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize =
    execution.N_BUS_CYCLES * N_ACCESS_COLUMNS;
pub const N_EXECUTION_SUMS: usize = execution.N_BUS_CYCLES;
pub const N_EXECUTION_COLUMNS: usize = 4 * N_EXECUTION_SUMS;
pub const N_BOUNDARY_COLUMNS: usize = 4;
pub const N_INTERACTION_COLUMNS: usize =
    N_EXECUTION_COLUMNS + N_BOUNDARY_COLUMNS;
pub const N_CONSTRAINTS: usize =
    execution.N_BUS_CYCLES * (N_DIFF_BITS + 10);
comptime {
    std.debug.assert(KEY_COUNT == 0x18000);
    std.debug.assert(BOUNDARY_SIZE == 0x20000);
}
pub const SramImage = image.SramImage;
pub const Images = image.Images;
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
    address: u17 = 0,
    previous_clock: u32 = 0,
    previous_value: u8 = 0,
    clock: u32 = 0,
    next_value: u8 = 0,
};

pub fn AccessRow(comptime S: type) type {
    return struct {
        previous_clock: S,
        previous_value: S,
        next_value: S,
        difference_bits: [N_DIFF_BITS]S,
        enabled: S,
        read: S,
        write: S,
        key: S,
        value: S,
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        accesses: [execution.N_BUS_CYCLES]AccessRow(S),

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidMainTraceShape;
            var accesses: [execution.N_BUS_CYCLES]AccessRow(S) = undefined;
            for (&accesses, 0..) |*access, cycle| {
                const offset = cycle * N_ACCESS_COLUMNS;
                access.* = .{
                    .previous_clock = values[offset + PREVIOUS_CLOCK_OFFSET],
                    .previous_value = values[offset + PREVIOUS_VALUE_OFFSET],
                    .next_value = values[offset + NEXT_VALUE_OFFSET],
                    .difference_bits = values[offset + DIFFERENCE_BITS_OFFSET ..][0..N_DIFF_BITS].*,
                    .enabled = values[offset + PROJECTED_ENABLED_OFFSET],
                    .read = values[offset + PROJECTED_READ_OFFSET],
                    .write = values[offset + PROJECTED_WRITE_OFFSET],
                    .key = values[offset + PROJECTED_KEY_OFFSET],
                    .value = values[offset + PROJECTED_VALUE_OFFSET],
                };
            }
            return .{ .accesses = accesses };
        }
    };
}

fn Projection(comptime S: type) type {
    return struct {
        enabled: S,
        read: S,
        write: S,
        key: S,
        value: S,
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

        pub fn evaluate(
            machine: execution.Row(S),
            sources: [execution.N_BUS_CYCLES]cartridge_access.Semantics(S).Row,
            row: Row(S),
        ) Evaluation {
            const one = S.one();
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            for (sources, row.accesses, 0..) |source, access, cycle_index| {
                const projected = project(source);
                out[at] = access.enabled.sub(projected.enabled);
                at += 1;
                out[at] = access.read.sub(projected.read);
                at += 1;
                out[at] = access.write.sub(projected.write);
                at += 1;
                out[at] = access.key.sub(projected.key);
                at += 1;
                out[at] = access.value.sub(projected.value);
                at += 1;
                var difference = S.zero();
                for (access.difference_bits, 0..) |bit_value, bit_index| {
                    out[at] = bit_value.mul(
                        bit_value.sub(access.enabled),
                    );
                    at += 1;
                    difference = difference.add(
                        base(@as(u64, 1) << @intCast(bit_index))
                            .mul(bit_value),
                    );
                }
                out[at] = one.sub(access.enabled)
                    .mul(access.previous_clock);
                at += 1;
                out[at] = one.sub(access.enabled)
                    .mul(access.previous_value);
                at += 1;
                const access_clock = memory_clock.fieldClock(
                    S,
                    machine.mcycle_before.add(base(cycle_index)),
                    memory_clock.CPU_PHASE,
                );
                out[at] = access.enabled.mul(
                    access_clock.sub(access.previous_clock)
                        .sub(one).sub(difference),
                );
                at += 1;
                out[at] = access.read.mul(
                    access.value.sub(access.previous_value),
                );
                at += 1;
                out[at] = access.next_value.sub(
                    access.read.mul(access.previous_value)
                        .add(access.write.mul(access.value)),
                );
                at += 1;
            }
            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        pub fn project(
            source: cartridge_access.Semantics(S).Row,
        ) Projection(S) {
            const sram =
                source.regions[
                    @intFromEnum(
                        runner.cartridge_memory.Region.cartridge_ram,
                    )
                ];
            const echo =
                source.regions[
                    @intFromEnum(
                        runner.cartridge_memory.Region.system_echo,
                    )
                ];
            const system =
                source.regions[
                    @intFromEnum(
                        runner.cartridge_memory.Region.system,
                    )
                ];
            const enabled = sram.add(echo).add(system);
            const read = enabled.mul(
                source.access_actions[
                    @intFromEnum(
                        runner.cartridge_memory.Action.read,
                    )
                ],
            );
            const write = enabled.mul(
                source.access_actions[
                    @intFromEnum(
                        runner.cartridge_memory.Action.write,
                    )
                ],
            );
            const logical = compose(source.logical_address);
            const physical = compose(source.physical_offset);
            return .{
                .enabled = enabled,
                .read = read,
                .write = write,
                .key = system.mul(logical)
                    .add(echo.mul(physical))
                    .add(sram.mul(base(SRAM_KEY_OFFSET).add(physical))),
                .value = compose(source.access_value),
            };
        }

        fn compose(bits: anytype) S {
            var result = S.zero();
            for (bits, 0..) |value, index| {
                result = result.add(
                    base(@as(u64, 1) << @intCast(index)).mul(value),
                );
            }
            return result;
        }

        fn base(value: anytype) S {
            const lifted = M31.fromU64(@intCast(value));
            if (S == M31) return lifted;
            return S.fromBase(lifted);
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
    steps: []const runner.CartridgeStepTrace,
    initial: Images,
    final: Images,
) !Witness {
    try validateImageShapes(initial, final);
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
    errdefer for (result.main[0..initialized]) |column|
        allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    result.final_clocks = try allocator.alloc(M31, BOUNDARY_SIZE);
    errdefer allocator.free(result.final_clocks);
    @memset(result.final_clocks, M31.zero());
    result.accesses = try allocator.alloc(
        Access,
        steps.len * execution.N_BUS_CYCLES,
    );
    errdefer allocator.free(result.accesses);
    @memset(result.accesses, Access{});

    const bytes = try allocator.alloc(u8, KEY_COUNT);
    defer allocator.free(bytes);
    @memcpy(bytes[0..SYSTEM_SIZE], initial.system.bytes);
    @memcpy(bytes[SYSTEM_SIZE..KEY_COUNT], initial.sram.bytes);
    const clocks = try allocator.alloc(u32, KEY_COUNT);
    defer allocator.free(clocks);
    @memset(clocks, 0);

    var mcycle: u32 = 0;
    for (steps, 0..) |step, row_index| {
        const validated = try cartridge_access.ValidatedStep.init(step);
        for (step.accesses[step.instruction.cycle_count..]) |tail|
            if (tail != null) return error.InvalidInactiveAccess;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row_index,
        );
        for (accessColumns(validated), 0..) |source_values, cycle_index| {
            const source =
                try cartridge_access.Semantics(M31).Row.fromColumns(
                    &source_values,
                );
            const projected = Semantics(M31).project(source);
            const offset = cycle_index * N_ACCESS_COLUMNS;
            result.main[offset + PROJECTED_ENABLED_OFFSET][storage] =
                projected.enabled;
            result.main[offset + PROJECTED_READ_OFFSET][storage] =
                projected.read;
            result.main[offset + PROJECTED_WRITE_OFFSET][storage] =
                projected.write;
            result.main[offset + PROJECTED_KEY_OFFSET][storage] =
                projected.key;
            result.main[offset + PROJECTED_VALUE_OFFSET][storage] =
                projected.value;
        }
        for (step.activeAccesses(), 0..) |maybe_access, cycle_index| {
            const access = maybe_access orelse continue;
            const key = try mutableKey(access) orelse continue;
            const access_clock = memory_clock.cpuClock(
                mcycle,
                cycle_index,
            ) catch return error.MemoryClockOverflow;
            const previous_clock = clocks[key];
            if (previous_clock >= access_clock)
                return error.InvalidMemoryClock;
            const previous_value = bytes[key];
            if (access.action == .read and access.value != previous_value)
                return error.MemoryReadMismatch;
            const difference = access_clock - previous_clock - 1;
            if (difference >= (@as(u32, 1) << N_DIFF_BITS))
                return error.MemoryClockDifferenceTooLarge;
            const next_value = if (access.action == .write)
                access.value
            else
                previous_value;
            if (access.action == .write) bytes[key] = access.value;
            clocks[key] = access_clock;

            const flat_index =
                row_index * execution.N_BUS_CYCLES + cycle_index;
            result.accesses[flat_index] = .{
                .enabled = true,
                .address = key,
                .previous_clock = previous_clock,
                .previous_value = previous_value,
                .clock = access_clock,
                .next_value = next_value,
            };
            const offset = cycle_index * N_ACCESS_COLUMNS;
            result.main[offset + PREVIOUS_CLOCK_OFFSET][storage] =
                M31.fromCanonical(previous_clock);
            result.main[offset + PREVIOUS_VALUE_OFFSET][storage] =
                M31.fromCanonical(previous_value);
            result.main[offset + NEXT_VALUE_OFFSET][storage] =
                M31.fromCanonical(next_value);
            for (0..N_DIFF_BITS) |bit_index| {
                result.main[
                    offset + DIFFERENCE_BITS_OFFSET + bit_index
                ][storage] =
                    M31.fromCanonical(
                        (difference >> @intCast(bit_index)) & 1,
                    );
            }
        }
        mcycle = std.math.add(
            u32,
            mcycle,
            step.instruction.cycle_count,
        ) catch return error.MemoryClockOverflow;
    }
    if (!std.mem.eql(
        u8,
        bytes[0..SYSTEM_SIZE],
        final.system.bytes,
    ) or !std.mem.eql(
        u8,
        bytes[SYSTEM_SIZE..KEY_COUNT],
        final.sram.bytes,
    )) return error.FinalMemoryMismatch;

    for (clocks, 0..) |clock, key| {
        result.final_clocks[
            try core_air_utils.circleBitReversedIndex(
                BOUNDARY_LOG_SIZE,
                key,
            )
        ] = M31.fromCanonical(clock);
    }
    return result;
}

pub fn accessColumns(
    step: cartridge_access.ValidatedStep,
) [execution.N_BUS_CYCLES][cartridge_access.N_MAIN_COLUMNS]M31 {
    var result =
        [_][cartridge_access.N_MAIN_COLUMNS]M31{
            cartridge_access.inactiveColumns(),
        } ** execution.N_BUS_CYCLES;
    for (0..step.trace.instruction.cycle_count) |cycle|
        result[cycle] = cartridge_access.columnsForCycle(step, cycle);
    return result;
}

pub fn evaluate(
    machine_values: [execution.N_MAIN_COLUMNS]M31,
    source_values: [execution.N_BUS_CYCLES][cartridge_access.N_MAIN_COLUMNS]M31,
    main_values: [N_MAIN_COLUMNS]M31,
) !Shipped.Evaluation {
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    var sources: [execution.N_BUS_CYCLES]cartridge_access.Semantics(QM31).Row =
        undefined;
    var main: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine, machine_values) |*value, source|
        value.* = QM31.fromBase(source);
    for (&sources, source_values) |*row, values| {
        var lifted: [cartridge_access.N_MAIN_COLUMNS]QM31 = undefined;
        for (&lifted, values) |*value, source|
            value.* = QM31.fromBase(source);
        row.* = try cartridge_access.Semantics(QM31).Row.fromColumns(
            &lifted,
        );
    }
    for (&main, main_values) |*value, source|
        value.* = QM31.fromBase(source);
    return Shipped.evaluate(
        try execution.Row(QM31).fromColumns(&machine),
        sources,
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

pub const BoundaryEntry = struct {
    enabled: bool,
    address: u17,
    initial_value: u8,
    final_clock: u32,
    final_value: u8,
};

pub fn boundaryEntry(
    row: usize,
    initial: Images,
    final_clocks: []const u32,
    final: Images,
) !BoundaryEntry {
    try validateImageShapes(initial, final);
    if (row >= BOUNDARY_SIZE) return error.InvalidBoundaryRow;
    if (final_clocks.len != KEY_COUNT) return error.InvalidBoundaryClocks;
    if (row >= KEY_COUNT) return .{
        .enabled = false,
        .address = 0,
        .initial_value = 0,
        .final_clock = 0,
        .final_value = 0,
    };
    return .{
        .enabled = true,
        .address = @intCast(row),
        .initial_value = imageByte(initial, row),
        .final_clock = final_clocks[row],
        .final_value = imageByte(final, row),
    };
}

pub fn boundaryPairForRow(
    row: usize,
    entry: BoundaryEntry,
    relation: Relation,
) !RowPair {
    if (row >= BOUNDARY_SIZE) return error.InvalidBoundaryRow;
    if (row < KEY_COUNT) {
        if (!entry.enabled or entry.address != row)
            return error.InvalidBoundaryEntry;
    } else if (entry.enabled or entry.address != 0 or
        entry.initial_value != 0 or entry.final_clock != 0 or
        entry.final_value != 0)
    {
        return error.InvalidBoundaryPadding;
    }
    if (!entry.enabled) return neutralPair();
    return .{
        .n1 = QM31.one(),
        .d1 = relation.combine(
            q(entry.address),
            QM31.zero(),
            q(entry.initial_value),
        ),
        .n2 = QM31.one().neg(),
        .d2 = relation.combine(
            q(entry.address),
            q(entry.final_clock),
            q(entry.final_value),
        ),
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

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Interaction) void {
        self.owned = false;
    }

    pub fn deinit(self: *Interaction) void {
        if (self.owned)
            for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn executionPairs(
    machine: execution.Row(QM31),
    _: [execution.N_BUS_CYCLES]cartridge_access.Semantics(QM31).Row,
    main: Row(QM31),
    relation: Relation,
) [N_EXECUTION_SUMS]RowPair {
    var result: [N_EXECUTION_SUMS]RowPair = undefined;
    for (&result, main.accesses, 0..) |
        *pair,
        access,
        index,
    | {
        const access_clock = memory_clock.fieldClock(
            QM31,
            machine.mcycle_before.add(q(index)),
            memory_clock.CPU_PHASE,
        );
        pair.* = .{
            .n1 = access.enabled.neg(),
            .d1 = relation.combine(
                access.key,
                access.previous_clock,
                access.previous_value,
            ),
            .n2 = access.enabled,
            .d2 = relation.combine(
                access.key,
                access_clock,
                access.next_value,
            ),
        };
    }
    return result;
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    accesses: []const Access,
    execution_log_size: u32,
    initial: Images,
    final: Images,
    relation: Relation,
) !Interaction {
    try validateImageShapes(initial, final);
    const execution_size =
        @as(usize, 1) << @intCast(execution_log_size);
    if (accesses.len != execution_size * execution.N_BUS_CYCLES)
        return error.InvalidTraceLength;
    const final_clocks = try allocator.alloc(u32, KEY_COUNT);
    defer allocator.free(final_clocks);
    @memset(final_clocks, 0);
    for (accesses) |access| {
        try validateAccess(access);
        if (access.enabled) final_clocks[access.address] = access.clock;
    }

    var columns: [N_INTERACTION_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column|
        allocator.free(column);
    for (columns[0..N_EXECUTION_COLUMNS]) |*column| {
        column.* = try allocator.alloc(M31, execution_size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (columns[N_EXECUTION_COLUMNS..]) |*column| {
        column.* = try allocator.alloc(M31, BOUNDARY_SIZE);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var execution_claims: [N_EXECUTION_SUMS]QM31 = undefined;
    for (0..N_EXECUTION_SUMS) |sum_index| {
        var accumulator = QM31.zero();
        for (0..execution_size) |row| {
            accumulator = try accumulate(
                accumulator,
                try accessPair(
                    accesses[row * execution.N_BUS_CYCLES + sum_index],
                    relation,
                ),
            );
            writeSecure(
                columns[4 * sum_index ..][0..4],
                try core_air_utils.circleBitReversedIndex(
                    execution_log_size,
                    row,
                ),
                accumulator,
            );
        }
        execution_claims[sum_index] = accumulator;
    }

    var boundary_claim = QM31.zero();
    for (0..BOUNDARY_SIZE) |row| {
        boundary_claim = try accumulate(
            boundary_claim,
            try boundaryPairForRow(
                row,
                try boundaryEntry(row, initial, final_clocks, final),
                relation,
            ),
        );
        writeSecure(
            columns[N_EXECUTION_COLUMNS..][0..4],
            try core_air_utils.circleBitReversedIndex(
                BOUNDARY_LOG_SIZE,
                row,
            ),
            boundary_claim,
        );
    }
    return .{
        .columns = columns,
        .claims = .{
            .execution = execution_claims,
            .boundary = boundary_claim,
        },
        .allocator = allocator,
    };
}

pub fn verifyCancellation(claims: Claims) !void {
    if (!claims.total().isZero())
        return error.CartridgeMemoryLookupSumNonZero;
}

fn mutableKey(access: runner.cartridge_memory.Access) !?u17 {
    return switch (access.region) {
        .system => if (access.physical_offset == null)
            @intCast(access.logical_address)
        else
            error.InvalidMutableAddress,
        .system_echo => if (access.physical_offset) |physical|
            if (physical < SYSTEM_SIZE)
                @intCast(physical)
            else
                error.InvalidMutableAddress
        else
            error.InvalidMutableAddress,
        .cartridge_ram => if (access.physical_offset) |physical|
            if (physical < SRAM_SIZE)
                @intCast(SRAM_KEY_OFFSET + physical)
            else
                error.InvalidMutableAddress
        else
            error.InvalidMutableAddress,
        .cartridge_rom,
        .mapper_control,
        .cartridge_open_bus,
        .cartridge_ram_ignored,
        .joypad_mmio,
        .timer_mmio,
        .ppu_mmio,
        .apu_mmio,
        => null,
    };
}

fn validateAccess(access: Access) !void {
    if (!access.enabled) {
        if (access.address != 0 or access.previous_clock != 0 or
            access.previous_value != 0 or access.clock != 0 or
            access.next_value != 0)
            return error.InvalidInactiveAccess;
        return;
    }
    if (access.address >= KEY_COUNT) return error.InvalidMutableAddress;
    if (access.previous_clock >= access.clock)
        return error.InvalidMemoryClock;
    if (access.clock - access.previous_clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.MemoryClockDifferenceTooLarge;
}

fn accessPair(access: Access, relation: Relation) !RowPair {
    try validateAccess(access);
    if (!access.enabled) return neutralPair();
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

fn neutralPair() RowPair {
    return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

fn accumulate(current: QM31, pair: RowPair) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero()) return current;
    if (pair.d1.eql(pair.d2) and pair.n1.add(pair.n2).isZero())
        return current;
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.CartridgeMemoryLookupZeroDenominator));
}

fn imageByte(images: Images, key: usize) u8 {
    std.debug.assert(key < KEY_COUNT);
    if (key < SYSTEM_SIZE) return images.system.bytes[key];
    return images.sram.bytes[key - SRAM_KEY_OFFSET];
}

fn validateImageShapes(initial: Images, final: Images) !void {
    if (initial.system.bytes.len != SYSTEM_SIZE or
        final.system.bytes.len != SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (initial.sram.bytes.len != SRAM_SIZE or final.sram.bytes.len != SRAM_SIZE)
        return error.InvalidSramShape;
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    const coordinates = value.toM31Array();
    for (columns, coordinates) |column, coordinate|
        column[row] = coordinate;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
