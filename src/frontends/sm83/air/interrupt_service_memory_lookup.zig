//! Interrupt-service logical IE/IF operations in cartridge memory.
//!
//! These rows authenticate SameBoy's logical resamples and acknowledgement;
//! they do not add CPU bus accesses. The low-stack FF0F alias is tied to the
//! CPU memory row's previous endpoint.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const service_air = @import("interrupt_service.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const machine_replay = @import("../machine_memory_replay.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");

pub const N_OPERATIONS: usize = 3;
pub const N_DIFF_BITS: usize = memory_lookup.N_DIFF_BITS;
pub const PREVIOUS_CLOCK_OFFSET: usize = 0;
pub const DIFFERENCE_BITS_OFFSET: usize = 1;
pub const N_OPERATION_COLUMNS: usize =
    DIFFERENCE_BITS_OFFSET + N_DIFF_BITS;
pub const SOURCE_CLOCK_OFFSET: usize =
    N_OPERATIONS * N_OPERATION_COLUMNS;
pub const N_MAIN_COLUMNS: usize = SOURCE_CLOCK_OFFSET + 1;
pub const N_CONSTRAINTS: usize =
    3 + N_MAIN_COLUMNS + N_OPERATIONS * (N_DIFF_BITS + 2) + 6;
pub const N_INTERACTION_COLUMNS: usize = N_OPERATIONS * 4 + 1;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Operation = enum(usize) {
    ie_resample,
    if_resample,
    acknowledgement,
};

pub const Boundary = struct {
    initial_mcycle: u32,
    final_mcycle: u32,
    expected_service_count: u32,
};

pub const Sample = struct {
    enabled: bool = false,
    previous_clock: u32 = 0,
    previous_value: u8 = 0,
    clock: u32 = 0,
    next_value: u8 = 0,
};

pub const RowSamples = struct {
    active: bool = false,
    operations: [N_OPERATIONS]Sample =
        [_]Sample{.{}} ** N_OPERATIONS,
};

pub fn OperationRow(comptime S: type) type {
    return struct {
        previous_clock: S,
        difference_bits: [N_DIFF_BITS]S,
    };
}

pub fn Row(comptime S: type) type {
    return struct {
        operations: [N_OPERATIONS]OperationRow(S),
        source_clock: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_MAIN_COLUMNS)
                return error.InvalidServiceMemoryShape;
            var operations: [N_OPERATIONS]OperationRow(S) = undefined;
            for (&operations, 0..) |*operation, index| {
                const offset = index * N_OPERATION_COLUMNS;
                operation.* = .{
                    .previous_clock = values[offset + PREVIOUS_CLOCK_OFFSET],
                    .difference_bits = values[offset + DIFFERENCE_BITS_OFFSET ..][0..N_DIFF_BITS].*,
                };
            }
            return .{
                .operations = operations,
                .source_clock = values[SOURCE_CLOCK_OFFSET],
            };
        }
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
    execution_values: []const S,
    service_values: []const S,
    memory_values: []const S,
    lookup_values: []const S,
    active: S,
) !Evaluation(S) {
    const executed = try execution.Row(S).fromColumns(execution_values);
    const service = try service_air.Shipped.Row.fromColumns(service_values);
    const memory = try memory_lookup.Row(S).fromColumns(memory_values);
    const row = try Row(S).fromColumns(lookup_values);
    const one = S.one();
    var selected = S.zero();
    for (service.selected) |value| selected = selected.add(value);
    const enabled = [_]S{ active, active, selected };
    const clocks = operationClocks(S, executed, service);
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    out[at] = bit(active);
    at += 1;
    out[at] = bit(selected);
    at += 1;
    out[at] = selected.mul(one.sub(active));
    at += 1;
    for (row.operations, enabled, clocks) |operation, is_enabled, clock| {
        var difference = S.zero();
        var power = S.one();
        for (operation.difference_bits) |bit_value| {
            out[at] = bit_value.mul(bit_value.sub(is_enabled));
            at += 1;
            difference = difference.add(power.mul(bit_value));
            power = power.add(power);
        }
        out[at] = active.sub(is_enabled).mul(operation.previous_clock);
        at += 1;
        out[at] = is_enabled.mul(
            clock.sub(operation.previous_clock).sub(one).sub(difference),
        );
        at += 1;
    }
    for (rowToColumns(S, row)) |value| {
        out[at] = one.sub(active).mul(value);
        at += 1;
    }

    const alias = service.low_is_if;
    const halted = executed.before.at(.halted);
    const low = selectLowAccess(S, memory, halted);
    const if_predecessor =
        row.operations[@intFromEnum(Operation.if_resample)];
    const source_value = ifSourceValue(S, service);
    const if_value = ifPostValue(S, service);
    out[at] = row.source_clock.sub(
        alias.mul(low.previous_clock)
            .add(active.sub(alias).mul(if_predecessor.previous_clock)),
    );
    at += 1;
    out[at] = source_value.sub(
        alias.mul(low.previous_value)
            .add(active.sub(alias).mul(if_value)),
    );
    at += 1;
    out[at] = alias.mul(low.enabled.sub(one));
    at += 1;
    out[at] = alias.mul(low.write.sub(one));
    at += 1;
    out[at] = alias.mul(low.read);
    at += 1;
    out[at] = alias.mul(low.key.sub(constant(S, 0xff0f)));
    at += 1;
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(
    result: machine.CartridgeStepResult,
    mcycle: u32,
    predecessors: machine_replay.ServicePredecessors,
) ![N_MAIN_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    if (result.event != .interrupt_service) {
        if (!predecessorsAreEmpty(predecessors))
            return error.InvalidInactiveServicePredecessor;
        return out;
    }
    const validated = service_air.ValidatedStep.init(result) catch
        return error.InvalidInterruptService;
    const service = validated.result.service;
    const ie = predecessors.ie_resample orelse
        return error.MissingServiceIePredecessor;
    const source = predecessors.if_logical_source orelse
        return error.MissingServiceIfSourcePredecessor;
    const interrupt_flags = predecessors.if_resample orelse
        return error.MissingServiceIfPredecessor;
    const ie_value = service.ie_resample.?.value;
    const source_value = concreteIfSourceValue(result);
    const if_value = concreteIfPostValue(result);
    if (ie.value != ie_value or source.value != source_value or
        interrupt_flags.value != if_value)
        return error.ServiceMemoryValueMismatch;

    const ie_clock = try operationClock(
        mcycle,
        service.ie_resample.?.after_cycle,
        memory_lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
    );
    const if_clock = try operationClock(
        mcycle,
        service.if_resample.?.after_cycle,
        memory_lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
    );
    try writeOperation(&out, .ie_resample, ie, ie_clock);
    try writeOperation(&out, .if_resample, interrupt_flags, if_clock);
    out[SOURCE_CLOCK_OFFSET] = M31.fromCanonical(source.clock);

    if (service.acknowledgement) |ack| {
        const predecessor = predecessors.acknowledgement orelse
            return error.MissingServiceAcknowledgementPredecessor;
        if (predecessor.value != ack.before)
            return error.ServiceMemoryValueMismatch;
        const clock = try operationClock(
            mcycle,
            ack.during_cycle,
            memory_lookup.memory_clock.SERVICE_ACK_PHASE,
        );
        try writeOperation(&out, .acknowledgement, predecessor, clock);
    } else if (predecessors.acknowledgement != null) {
        return error.UnexpectedServiceAcknowledgementPredecessor;
    }
    return out;
}

pub const Witness = struct {
    log_size: u32,
    main: [N_MAIN_COLUMNS][]M31,
    samples: []RowSamples,
    service_count: u32,
    allocator: std.mem.Allocator,
    main_owned: bool = true,

    pub fn disownColumns(self: *Witness) void {
        self.main_owned = false;
    }

    pub fn deinit(self: *Witness) void {
        if (self.main_owned)
            for (self.main) |column| self.allocator.free(column);
        self.allocator.free(self.samples);
        self.* = undefined;
    }
};

pub fn generateWitness(
    allocator: std.mem.Allocator,
    results: []const machine.CartridgeStepResult,
    boundary: Boundary,
    predecessors: []const machine_replay.ServicePredecessors,
) !Witness {
    try validateBoundary(boundary);
    if (results.len < 16 or !std.math.isPowerOfTwo(results.len))
        return error.InvalidServiceMemoryTraceLength;
    if (predecessors.len != results.len)
        return error.InvalidServicePredecessorCount;
    const log_size: u32 =
        @intCast(std.math.log2_int(usize, results.len));
    var witness = Witness{
        .log_size = log_size,
        .main = undefined,
        .samples = try allocator.alloc(RowSamples, results.len),
        .service_count = 0,
        .allocator = allocator,
    };
    errdefer allocator.free(witness.samples);
    @memset(witness.samples, RowSamples{});
    var initialized: usize = 0;
    errdefer for (witness.main[0..initialized]) |column|
        allocator.free(column);
    for (&witness.main) |*column| {
        column.* = try allocator.alloc(M31, results.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var mcycle = boundary.initial_mcycle;
    for (results, predecessors, 0..) |result, row_predecessors, row_index| {
        if (!result.hasCanonicalShape())
            return error.InvalidMachineStep;
        const values = try columns(result, mcycle, row_predecessors);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row_index,
        );
        for (witness.main, values) |column, value|
            column[storage] = value;
        witness.samples[row_index] = try samples(
            result,
            mcycle,
            row_predecessors,
        );
        if (result.event == .interrupt_service)
            witness.service_count += 1;
        mcycle = std.math.add(u32, mcycle, result.m_cycles) catch
            return error.ServiceMemoryClockOverflow;
    }
    if (mcycle != boundary.final_mcycle)
        return error.InvalidServiceMemoryFinalClock;
    if (witness.service_count != boundary.expected_service_count)
        return error.ServiceCountMismatch;
    return witness;
}

pub fn evaluateM31(
    execution_values: [execution.N_MAIN_COLUMNS]M31,
    service_values: [service_air.N_MAIN_COLUMNS]M31,
    memory_values: [memory_lookup.N_MAIN_COLUMNS]M31,
    lookup_values: [N_MAIN_COLUMNS]M31,
    active: bool,
) !Evaluation(QM31) {
    var executed: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    var service: [service_air.N_MAIN_COLUMNS]QM31 = undefined;
    var memory: [memory_lookup.N_MAIN_COLUMNS]QM31 = undefined;
    var lookup: [N_MAIN_COLUMNS]QM31 = undefined;
    lift(&executed, &execution_values);
    lift(&service, &service_values);
    lift(&memory, &memory_values);
    lift(&lookup, &lookup_values);
    return evaluate(
        QM31,
        &executed,
        &service,
        &memory,
        &lookup,
        booleanQ(active),
    );
}

pub const Claims = struct {
    operations: [N_OPERATIONS]QM31,
    service_count: u32,

    pub fn total(self: Claims) QM31 {
        var value = QM31.zero();
        for (self.operations) |claim| value = value.add(claim);
        return value;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    rows: []const RowSamples,
    log_size: u32,
    relation: memory_lookup.Relation,
) !Interaction {
    const size = try traceSize(log_size);
    if (rows.len != size) return error.InvalidServiceMemoryTraceLength;
    var result = Interaction{
        .columns = undefined,
        .claims = .{
            .operations = [_]QM31{QM31.zero()} ** N_OPERATIONS,
            .service_count = 0,
        },
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
    for (rows, 0..) |row, row_index| {
        if (row.active !=
            (row.operations[0].enabled and row.operations[1].enabled) or
            (!row.active and row.operations[2].enabled))
            return error.InvalidServiceActivity;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row_index,
        );
        if (row.active) result.claims.service_count += 1;
        for (row.operations, 0..) |sample, index| {
            result.claims.operations[index] = try accumulate(
                result.claims.operations[index],
                try pairForSample(@enumFromInt(index), sample, relation),
            );
            writeSecure(
                result.columns[4 * index ..][0..4],
                storage,
                result.claims.operations[index],
            );
        }
        result.columns[N_INTERACTION_COLUMNS - 1][storage] =
            M31.fromCanonical(result.claims.service_count);
    }
    return result;
}

pub fn pairsForRows(
    executed: execution.Row(QM31),
    service: service_air.Shipped.Row,
    row: Row(QM31),
    active: QM31,
    relation: memory_lookup.Relation,
) [N_OPERATIONS]memory_lookup.RowPair {
    var selected = QM31.zero();
    for (service.selected) |value| selected = selected.add(value);
    const enabled = [_]QM31{ active, active, selected };
    const clocks = operationClocks(QM31, executed, service);
    const previous_values = [_]QM31{
        compose(service.ie_sample),
        ifPostValue(QM31, service),
        compose(service.ack_before),
    };
    const next_values = [_]QM31{
        previous_values[0],
        previous_values[1],
        compose(service.ack_after),
    };
    var pairs: [N_OPERATIONS]memory_lookup.RowPair = undefined;
    for (
        &pairs,
        row.operations,
        enabled,
        clocks,
        previous_values,
        next_values,
        0..,
    ) |
        *pair,
        operation,
        is_enabled,
        clock,
        previous_value,
        next_value,
        index,
    | {
        pair.* = pairAddress(
            @enumFromInt(index),
            relation,
            operation.previous_clock,
            previous_value,
            clock,
            next_value,
            is_enabled,
        );
    }
    return pairs;
}

pub fn verifyCancellation(
    memory_claims: memory_lookup.Claims,
    service_claims: Claims,
) !void {
    if (!memory_claims.total().add(service_claims.total()).isZero())
        return error.ServiceMemoryLookupSumNonZero;
}

pub fn activityConstraint(
    current: QM31,
    previous: QM31,
    active: QM31,
    is_first: QM31,
) QM31 {
    return current.sub(
        QM31.one().sub(is_first).mul(previous),
    ).sub(active);
}

pub fn activityBoundaryConstraint(
    current: QM31,
    is_last: QM31,
    expected: u32,
) QM31 {
    return is_last.mul(current.sub(q(expected)));
}

fn samples(
    result: machine.CartridgeStepResult,
    mcycle: u32,
    predecessors: machine_replay.ServicePredecessors,
) !RowSamples {
    _ = try columns(result, mcycle, predecessors);
    if (result.event != .interrupt_service) return .{};
    const service = result.service;
    const ie_clock = try operationClock(
        mcycle,
        service.ie_resample.?.after_cycle,
        memory_lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
    );
    const if_clock = try operationClock(
        mcycle,
        service.if_resample.?.after_cycle,
        memory_lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
    );
    var result_samples = RowSamples{ .active = true };
    result_samples.operations[@intFromEnum(Operation.ie_resample)] =
        readSample(
            predecessors.ie_resample.?,
            ie_clock,
        );
    result_samples.operations[@intFromEnum(Operation.if_resample)] =
        readSample(
            predecessors.if_resample.?,
            if_clock,
        );
    if (service.acknowledgement) |ack| {
        const clock = try operationClock(
            mcycle,
            ack.during_cycle,
            memory_lookup.memory_clock.SERVICE_ACK_PHASE,
        );
        result_samples.operations[
            @intFromEnum(Operation.acknowledgement)
        ] = .{
            .enabled = true,
            .previous_clock = predecessors.acknowledgement.?.clock,
            .previous_value = ack.before,
            .clock = clock,
            .next_value = ack.after,
        };
    }
    return result_samples;
}

fn operationClocks(
    comptime S: type,
    executed: execution.Row(S),
    service: service_air.Shipped.Row,
) [N_OPERATIONS]S {
    return .{
        memory_lookup.memory_clock.fieldClock(
            S,
            executed.mcycle_before.add(compose(service.ie_cycle_bits)),
            memory_lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
        ),
        memory_lookup.memory_clock.fieldClock(
            S,
            executed.mcycle_before.add(compose(service.if_cycle_bits)),
            memory_lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
        ),
        memory_lookup.memory_clock.fieldClock(
            S,
            executed.mcycle_before.add(compose(service.ack_cycle_bits)),
            memory_lookup.memory_clock.SERVICE_ACK_PHASE,
        ),
    };
}

fn writeOperation(
    out: *[N_MAIN_COLUMNS]M31,
    operation: Operation,
    predecessor: machine_replay.Predecessor,
    clock: u32,
) !void {
    if (predecessor.clock >= clock)
        return error.InvalidServiceMemoryClock;
    const difference = clock - predecessor.clock - 1;
    if (difference >= (@as(u32, 1) << N_DIFF_BITS))
        return error.ServiceMemoryClockDifferenceTooLarge;
    const offset = @intFromEnum(operation) * N_OPERATION_COLUMNS;
    out[offset + PREVIOUS_CLOCK_OFFSET] =
        M31.fromCanonical(predecessor.clock);
    writeBits(
        out[offset + DIFFERENCE_BITS_OFFSET ..][0..N_DIFF_BITS],
        difference,
    );
}

fn operationClock(mcycle: u32, cycle: u3, phase: u32) !u32 {
    const absolute = std.math.add(u32, mcycle, cycle) catch
        return error.ServiceMemoryClockOverflow;
    return memory_lookup.memory_clock.phaseClock(absolute, phase) catch |err|
        switch (err) {
            error.MemoryClockOverflow => error.ServiceMemoryClockOverflow,
            error.MemoryClockOutsideField,
            error.InvalidMemoryClockPhase,
            => error.NonCanonicalServiceMemoryClock,
        };
}

fn concreteIfSourceValue(result: machine.CartridgeStepResult) u8 {
    return (result.before.interrupt_flags & 0xe0) |
        result.service.if_resample.?.value;
}

fn concreteIfPostValue(result: machine.CartridgeStepResult) u8 {
    return if (result.before.cpu.sp -% 2 == 0xff0f)
        @truncate(result.before.cpu.pc)
    else
        concreteIfSourceValue(result);
}

fn ifSourceValue(
    comptime S: type,
    service: service_air.Shipped.Row,
) S {
    return compose(service.if_sample).add(
        constant(S, 32).mul(compose(service.if_before_high)),
    );
}

fn ifPostValue(
    comptime S: type,
    service: service_air.Shipped.Row,
) S {
    return compose(service.if_after_low).add(
        constant(S, 32).mul(compose(service.if_after[5..8].*)),
    );
}

fn selectLowAccess(
    comptime S: type,
    memory: memory_lookup.Row(S),
    halted: S,
) struct {
    previous_clock: S,
    previous_value: S,
    enabled: S,
    read: S,
    write: S,
    key: S,
} {
    const running = S.one().sub(halted);
    const first = memory.accesses[4];
    const second = memory.accesses[5];
    return .{
        .previous_clock = running.mul(first.previous_clock)
            .add(halted.mul(second.previous_clock)),
        .previous_value = running.mul(first.previous_value)
            .add(halted.mul(second.previous_value)),
        .enabled = running.mul(first.enabled)
            .add(halted.mul(second.enabled)),
        .read = running.mul(first.read)
            .add(halted.mul(second.read)),
        .write = running.mul(first.write)
            .add(halted.mul(second.write)),
        .key = running.mul(first.key)
            .add(halted.mul(second.key)),
    };
}

fn rowToColumns(comptime S: type, row: Row(S)) [N_MAIN_COLUMNS]S {
    var values: [N_MAIN_COLUMNS]S = undefined;
    for (row.operations, 0..) |operation, index| {
        const offset = index * N_OPERATION_COLUMNS;
        values[offset] = operation.previous_clock;
        @memcpy(
            values[offset + DIFFERENCE_BITS_OFFSET ..][0..N_DIFF_BITS],
            &operation.difference_bits,
        );
    }
    values[SOURCE_CLOCK_OFFSET] = row.source_clock;
    return values;
}

fn pairForSample(
    operation: Operation,
    sample: Sample,
    relation: memory_lookup.Relation,
) !memory_lookup.RowPair {
    try validateSample(sample);
    if (!sample.enabled) return neutralPair();
    return pairAddress(
        operation,
        relation,
        q(sample.previous_clock),
        q(sample.previous_value),
        q(sample.clock),
        q(sample.next_value),
        QM31.one(),
    );
}

fn operationAddress(operation: Operation) QM31 {
    return q(switch (operation) {
        .ie_resample => 0xffff,
        .if_resample, .acknowledgement => runner.cartridge_memory.INTERRUPT_FLAGS,
    });
}

fn readSample(
    predecessor: machine_replay.Predecessor,
    clock: u32,
) Sample {
    return .{
        .enabled = true,
        .previous_clock = predecessor.clock,
        .previous_value = predecessor.value,
        .clock = clock,
        .next_value = predecessor.value,
    };
}

fn validateSample(sample: Sample) !void {
    if (!sample.enabled) {
        if (!std.meta.eql(sample, Sample{}))
            return error.InvalidInactiveServiceSample;
        return;
    }
    if (sample.previous_clock >= sample.clock)
        return error.InvalidServiceMemoryClock;
    if (sample.clock - sample.previous_clock - 1 >=
        (@as(u32, 1) << N_DIFF_BITS))
        return error.ServiceMemoryClockDifferenceTooLarge;
}

fn predecessorsAreEmpty(
    predecessors: machine_replay.ServicePredecessors,
) bool {
    return predecessors.ie_resample == null and
        predecessors.if_logical_source == null and
        predecessors.if_resample == null and
        predecessors.acknowledgement == null;
}

fn validateBoundary(boundary: Boundary) !void {
    if (boundary.initial_mcycle >= boundary.final_mcycle)
        return error.InvalidServiceMemoryBoundary;
    if (boundary.final_mcycle >
        memory_lookup.memory_clock.MAX_FINAL_MCYCLE)
        return error.NonCanonicalServiceMemoryClock;
}

fn accumulate(
    current: QM31,
    pair: memory_lookup.RowPair,
) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero()) return current;
    const denominator = pair.d1.mul(pair.d2);
    const numerator =
        pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return current.add(numerator.mul(denominator.inv() catch
        return error.ServiceMemoryLookupZeroDenominator));
}

fn neutralPair() memory_lookup.RowPair {
    return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidServiceMemoryLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn writeBits(output: []M31, value: anytype) void {
    for (output, 0..) |*bit_value, index|
        bit_value.* = M31.fromCanonical(
            @intCast(value >> @intCast(index) & 1),
        );
}

fn compose(bits: anytype) @TypeOf(bits[0]) {
    const S = @TypeOf(bits[0]);
    var value = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        value = value.add(power.mul(bit_value));
        power = power.add(power);
    }
    return value;
}

fn constant(comptime S: type, value: anytype) S {
    const base = M31.fromU64(@intCast(value));
    return if (S == M31) base else S.fromBase(base);
}

fn bit(value: anytype) @TypeOf(value) {
    return value.mul(value.sub(@TypeOf(value).one()));
}

fn lift(output: []QM31, input: []const M31) void {
    for (output, input) |*value, source|
        value.* = QM31.fromBase(source);
}

fn pairAddress(
    operation: Operation,
    relation: memory_lookup.Relation,
    previous_clock: QM31,
    previous_value: QM31,
    clock: QM31,
    next_value: QM31,
    enabled: QM31,
) memory_lookup.RowPair {
    const address_value = operationAddress(operation);
    return .{
        .n1 = enabled.neg(),
        .d1 = relation.combine(
            address_value,
            previous_clock,
            previous_value,
        ),
        .n2 = enabled,
        .d2 = relation.combine(address_value, clock, next_value),
    };
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

fn booleanQ(value: bool) QM31 {
    return if (value) QM31.one() else QM31.zero();
}

fn writeSecure(output_columns: []const []M31, row: usize, value: QM31) void {
    for (output_columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}
