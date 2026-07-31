//! Ordered mutable-memory contributions for OAM DMA transfers.
//!
//! Supported sources are proof-addressable system memory: VRAM 8000..9FFF
//! and WRAM C000..DFFF (including E000..FFFF DMA aliases). ROM and cartridge
//! SRAM fail closed until a mapper-aware ROM/SRAM DMA relation exists.
//! Every supported transfer contributes one source read and one OAM write at
//! the shared `DMA_PHASE`.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const dma_runner = @import("../runner/dma.zig");
const binding = @import("dma_binding.zig");
const dma_air = @import("dma.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");

pub const N_VALUE_BITS: usize = 8;
pub const N_DIFF_BITS: usize = memory_lookup.N_DIFF_BITS;
pub const SOURCE_PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const SOURCE_PREVIOUS_VALUE_OFFSET: usize = 1;
pub const SOURCE_DIFFERENCE_BITS_OFFSET: usize =
    SOURCE_PREVIOUS_VALUE_OFFSET + N_VALUE_BITS;
pub const DESTINATION_PREVIOUS_CLOCK_OFFSET: usize =
    SOURCE_DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const DESTINATION_PREVIOUS_VALUE_OFFSET: usize =
    DESTINATION_PREVIOUS_CLOCK_OFFSET + 1;
pub const DESTINATION_DIFFERENCE_BITS_OFFSET: usize =
    DESTINATION_PREVIOUS_VALUE_OFFSET + N_VALUE_BITS;
pub const N_MAIN_COLUMNS: usize =
    DESTINATION_DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const N_CONSTRAINTS: usize =
    2 * N_VALUE_BITS + 2 * N_DIFF_BITS + 6;
pub const N_INTERACTION_COLUMNS: usize = 8;

pub const Predecessor = struct {
    clock: u32 = 0,
    value: u8 = 0,
};

pub const Predecessors = struct {
    source: Predecessor = .{},
    destination: Predecessor = .{},
};

pub const AccessPair = struct {
    source: memory_lookup.Access = .{},
    destination: memory_lookup.Access = .{},
};

pub fn OperationRow(comptime S: type) type {
    return struct {
        previous_clock: S,
        previous_value: [N_VALUE_BITS]S,
        difference_bits: [N_DIFF_BITS]S,
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        source: OperationRow(S),
        destination: OperationRow(S),

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidDmaMemoryLookupShape;
            return .{
                .source = .{
                    .previous_clock = values[SOURCE_PREVIOUS_CLOCK_OFFSET],
                    .previous_value = values[SOURCE_PREVIOUS_VALUE_OFFSET..SOURCE_DIFFERENCE_BITS_OFFSET].*,
                    .difference_bits = values[SOURCE_DIFFERENCE_BITS_OFFSET..DESTINATION_PREVIOUS_CLOCK_OFFSET].*,
                },
                .destination = .{
                    .previous_clock = values[DESTINATION_PREVIOUS_CLOCK_OFFSET],
                    .previous_value = values[DESTINATION_PREVIOUS_VALUE_OFFSET..DESTINATION_DIFFERENCE_BITS_OFFSET].*,
                    .difference_bits = values[DESTINATION_DIFFERENCE_BITS_OFFSET..N_MAIN_COLUMNS].*,
                },
            };
        }
    };
}

pub fn DmaRow(comptime S: type) type {
    return struct {
        active: S,
        semantic: dma_air.Semantics(S).Row,
        mcycle: S,
        page_vram: S,
    };
}

pub fn dmaRow(
    comptime S: type,
    values: []const S,
) !DmaRow(S) {
    if (values.len != binding.N_MAIN_COLUMNS)
        return error.InvalidDmaBindingShape;
    return .{
        .active = values[0],
        .semantic = try dma_air.Semantics(S).Row.fromColumns(
            values[1..binding.MCYCLE_OFFSET],
        ),
        .mcycle = values[binding.MCYCLE_OFFSET],
        .page_vram = values[binding.PAGE_VRAM_OFFSET],
    };
}

pub fn Evaluation(comptime S: type) type {
    return struct {
        values: [N_CONSTRAINTS]S,

        pub fn allZero(self: @This()) bool {
            for (self.values) |value|
                if (!value.isZero()) return false;
            return true;
        }
    };
}

pub fn evaluate(
    comptime S: type,
    dma: DmaRow(S),
    row: Row(S),
) Evaluation(S) {
    const one = S.one();
    const enabled = dma.semantic.transfer_active;
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    for (row.source.previous_value, dma.semantic.transfer_value) |
        previous,
        transferred,
    | {
        out[at] = previous.sub(transferred);
        at += 1;
    }
    for (row.destination.previous_value) |value| {
        out[at] = value.mul(value.sub(enabled));
        at += 1;
    }
    var source_difference = S.zero();
    var destination_difference = S.zero();
    var power = one;
    for (
        row.source.difference_bits,
        row.destination.difference_bits,
    ) |source_bit, destination_bit| {
        out[at] = source_bit.mul(source_bit.sub(enabled));
        at += 1;
        out[at] = destination_bit.mul(
            destination_bit.sub(enabled),
        );
        at += 1;
        source_difference = source_difference.add(
            power.mul(source_bit),
        );
        destination_difference = destination_difference.add(
            power.mul(destination_bit),
        );
        power = power.add(power);
    }
    out[at] = one.sub(enabled).mul(row.source.previous_clock);
    at += 1;
    out[at] = one.sub(enabled).mul(
        row.destination.previous_clock,
    );
    at += 1;
    const clock = phasedClock(S, dma);
    out[at] = enabled.mul(
        clock.sub(row.source.previous_clock)
            .sub(one).sub(source_difference),
    );
    at += 1;
    out[at] = enabled.mul(
        clock.sub(row.destination.previous_clock)
            .sub(one).sub(destination_difference),
    );
    at += 1;
    const page = dma.semantic.before.page;
    out[at] = enabled.mul(
        one.sub(dma.page_vram)
            .sub(page[7].mul(page[6])),
    );
    at += 1;
    out[at] = enabled.mul(one.sub(dma.active));
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub const Witness = struct {
    log_size: u32,
    main: [N_MAIN_COLUMNS][]M31,
    accesses: []AccessPair,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disownColumns(self: *Witness) void {
        self.owned = false;
    }

    pub fn takeAccesses(self: *Witness) []AccessPair {
        const result = self.accesses;
        self.accesses = &.{};
        return result;
    }

    pub fn deinit(self: *Witness) void {
        if (self.owned)
            for (self.main) |column| self.allocator.free(column);
        if (self.accesses.len != 0) self.allocator.free(self.accesses);
        self.* = undefined;
    }
};

pub fn generateWitness(
    allocator: std.mem.Allocator,
    log_size: u32,
    events: []const binding.EventRow,
    predecessors: []const Predecessors,
) !Witness {
    const size = try traceSize(log_size);
    if (events.len == 0) return error.EmptyDmaTrace;
    if (events.len > size) return error.TooManyDmaEvents;
    if (predecessors.len != events.len)
        return error.InvalidDmaPredecessorCount;
    var result = Witness{
        .log_size = log_size,
        .main = undefined,
        .accesses = try allocator.alloc(AccessPair, size),
        .allocator = allocator,
    };
    errdefer allocator.free(result.accesses);
    @memset(result.accesses, AccessPair{});
    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column|
        allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (events, predecessors, 0..) |event, predecessor, index| {
        const accesses = try accessesForEvent(event, predecessor);
        result.accesses[index] = accesses;
        const values = try columnsForAccesses(accesses);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            index,
        );
        for (result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn accessesForEvent(
    event: binding.EventRow,
    predecessors: Predecessors,
) !AccessPair {
    event.transition.validate() catch
        return error.InvalidDmaTransition;
    const transfer = event.transition.transfer orelse {
        if (!std.meta.eql(predecessors, Predecessors{}))
            return error.InvalidInactiveDmaPredecessor;
        return .{};
    };
    if (!isMutableSystemSource(transfer.source_address))
        return error.UnsupportedDmaSourceRegion;
    if (predecessors.source.value != transfer.value)
        return error.InvalidDmaSourceValue;
    const clock = memory_lookup.memory_clock.phaseClock(
        event.mcycle,
        memory_lookup.memory_clock.DMA_PHASE,
    ) catch return error.NonCanonicalDmaMemoryClock;
    try validatePredecessor(predecessors.source, clock);
    try validatePredecessor(predecessors.destination, clock);
    return .{
        .source = .{
            .enabled = true,
            .address = transfer.source_address,
            .previous_clock = predecessors.source.clock,
            .previous_value = transfer.value,
            .clock = clock,
            .next_value = transfer.value,
        },
        .destination = .{
            .enabled = true,
            .address = transfer.destination_address,
            .previous_clock = predecessors.destination.clock,
            .previous_value = predecessors.destination.value,
            .clock = clock,
            .next_value = transfer.value,
        },
    };
}

pub fn columnsForAccesses(
    accesses: AccessPair,
) ![N_MAIN_COLUMNS]M31 {
    try validateAccess(accesses.source, true);
    try validateAccess(accesses.destination, false);
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    writeOperation(
        out[SOURCE_PREVIOUS_CLOCK_OFFSET..DESTINATION_PREVIOUS_CLOCK_OFFSET],
        accesses.source,
    );
    writeOperation(
        out[DESTINATION_PREVIOUS_CLOCK_OFFSET..N_MAIN_COLUMNS],
        accesses.destination,
    );
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

pub fn pairsForRows(
    dma: DmaRow(QM31),
    row: Row(QM31),
    relation: memory_lookup.Relation,
) [2]memory_lookup.RowPair {
    const enabled = dma.semantic.transfer_active;
    const value = compose(dma.semantic.transfer_value);
    const clock = phasedClock(QM31, dma);
    return .{
        .{
            .n1 = enabled.neg(),
            .d1 = relation.combine(
                compose(dma.semantic.source_address),
                row.source.previous_clock,
                value,
            ),
            .n2 = enabled,
            .d2 = relation.combine(
                compose(dma.semantic.source_address),
                clock,
                value,
            ),
        },
        .{
            .n1 = enabled.neg(),
            .d1 = relation.combine(
                compose(dma.semantic.destination_address),
                row.destination.previous_clock,
                compose(row.destination.previous_value),
            ),
            .n2 = enabled,
            .d2 = relation.combine(
                compose(dma.semantic.destination_address),
                clock,
                value,
            ),
        },
    };
}

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: [2]QM31,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    accesses: []const AccessPair,
    log_size: u32,
    relation: memory_lookup.Relation,
) !Interaction {
    const size = try traceSize(log_size);
    if (accesses.len != size) return error.InvalidTraceLength;
    var result = Interaction{
        .columns = undefined,
        .claims = .{ QM31.zero(), QM31.zero() },
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column|
        allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (accesses, 0..) |access_pair, index| {
        const pairs = [_]memory_lookup.RowPair{
            try accessPair(access_pair.source, relation, true),
            try accessPair(access_pair.destination, relation, false),
        };
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            index,
        );
        for (pairs, 0..) |pair, pair_index| {
            result.claims[pair_index] = try accumulate(
                result.claims[pair_index],
                pair,
            );
            writeSecure(
                result.columns[4 * pair_index ..][0..4],
                storage,
                result.claims[pair_index],
            );
        }
    }
    return result;
}

pub fn accumulate(
    current: QM31,
    pair: memory_lookup.RowPair,
) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero()) return current;
    const denominator = pair.d1.mul(pair.d2);
    const numerator =
        pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.DmaMemoryLookupZeroDenominator));
}

pub fn isMutableSystemSource(address: u16) bool {
    return (address >= 0x8000 and address < 0xa000) or
        (address >= 0xc000 and address < 0xe000);
}

fn accessPair(
    access: memory_lookup.Access,
    relation: memory_lookup.Relation,
    source_read: bool,
) !memory_lookup.RowPair {
    try validateAccess(access, source_read);
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

fn validatePredecessor(predecessor: Predecessor, clock: u32) !void {
    if (predecessor.clock >= clock)
        return error.InvalidDmaPredecessorClock;
    if (clock - predecessor.clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.DmaClockDifferenceTooLarge;
}

fn validateAccess(
    access: memory_lookup.Access,
    source_read: bool,
) !void {
    if (!access.enabled) {
        if (!std.meta.eql(access, memory_lookup.Access{}))
            return error.InvalidInactiveDmaAccess;
        return;
    }
    if (access.clock >= M31_MODULUS or
        access.previous_clock >= access.clock)
        return error.InvalidDmaPredecessorClock;
    if (access.clock - access.previous_clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.DmaClockDifferenceTooLarge;
    if (source_read and
        (access.previous_value != access.next_value or
            !isMutableSystemSource(@intCast(access.address))))
        return error.InvalidDmaSourceAccess;
    if (!source_read and
        (access.address < dma_runner.OAM_START or
            access.address >=
                dma_runner.OAM_START + dma_runner.OAM_LENGTH))
        return error.InvalidDmaDestinationAccess;
}

fn writeOperation(out: []M31, access: memory_lookup.Access) void {
    if (!access.enabled) return;
    out[0] = M31.fromCanonical(access.previous_clock);
    setBits(out[1 .. 1 + N_VALUE_BITS], access.previous_value);
    setBits(
        out[1 + N_VALUE_BITS ..],
        access.clock - access.previous_clock - 1,
    );
}

fn phasedClock(comptime S: type, dma: DmaRow(S)) S {
    return memory_lookup.memory_clock.fieldClock(
        S,
        dma.mcycle,
        memory_lookup.memory_clock.DMA_PHASE,
    );
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidDmaLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn setBits(target: []M31, value: anytype) void {
    const unsigned: u64 = @intCast(value);
    for (target, 0..) |*bit_value, index|
        bit_value.* = M31.fromCanonical(
            @intCast(unsigned >> @intCast(index) & 1),
        );
}

fn compose(bits: anytype) @TypeOf(bits[0]) {
    var result = @TypeOf(bits[0]).zero();
    var power = @TypeOf(bits[0]).one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn writeSecure(
    columns: []const []M31,
    row: usize,
    value: QM31,
) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
