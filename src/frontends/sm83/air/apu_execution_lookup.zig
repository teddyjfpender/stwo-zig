//! Ordered LogUp join between canonical execution accesses and APU transitions.
//!
//! The execution side selects exactly the cartridge-access rows classified as
//! `.apu_mmio`. The APU side supplies the same clock, ordinal, action, address,
//! and value tuple. The ordinal is constrained on both traces, so the lookup is
//! an ordered execution relation rather than only a permutation argument.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const runner = @import("../runner/mod.zig");
const apu = @import("../runner/apu_mmio.zig");
const binding = @import("apu_binding.zig");
const cartridge_access = @import("cartridge_access.zig");
const cartridge_access_component = @import("cartridge_access_component.zig");
const cartridge_machine_access = @import("cartridge_machine_access.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const scheduler_machine = @import("../runner/machine.zig");

pub const N_EXECUTION_SUMS: usize = execution.N_BUS_CYCLES;
pub const N_EXECUTION_AUXILIARY_COLUMNS: usize = 1;
pub const N_APU_AUXILIARY_COLUMNS: usize = 2;
pub const N_EXECUTION_INTERACTION_COLUMNS: usize =
    N_EXECUTION_SUMS * 4;
pub const N_APU_INTERACTION_COLUMNS: usize = 4;
pub const N_EXECUTION_ORDER_CONSTRAINTS: usize = 3;
pub const N_APU_ORDER_CONSTRAINTS: usize = 8;
pub const N_EXECUTION_CONSTRAINTS: usize =
    N_EXECUTION_SUMS + N_EXECUTION_ORDER_CONSTRAINTS;
pub const N_APU_CONSTRAINTS: usize = 1 + N_APU_ORDER_CONSTRAINTS;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

const RELATION_TAG: u32 = 0x4150_5501;

pub const ExecutionTrace = struct {
    semantic: binding.Trace,
    mcycles: []u32,
    final_execution_mcycle: u32,

    pub fn deinit(self: *ExecutionTrace, allocator: std.mem.Allocator) void {
        self.semantic.deinit(allocator);
        allocator.free(self.mcycles);
        self.* = undefined;
    }
};

pub const Relation = struct {
    z: QM31,
    clock_alpha: QM31,
    order_alpha: QM31,
    address_alpha: QM31,
    value_alpha: QM31,
    action_alpha: QM31,

    pub fn draw(
        allocator: std.mem.Allocator,
        channel: anytype,
    ) !Relation {
        channel.mixU32s(&.{RELATION_TAG});
        const values = try channel.drawSecureFelts(allocator, 6);
        defer allocator.free(values);
        return .{
            .z = values[0],
            .clock_alpha = values[1],
            .order_alpha = values[2],
            .address_alpha = values[3],
            .value_alpha = values[4],
            .action_alpha = values[5],
        };
    }

    pub fn combine(
        self: Relation,
        clock: QM31,
        order: QM31,
        address: QM31,
        value: QM31,
        action: QM31,
    ) QM31 {
        return self.clock_alpha.mul(clock)
            .add(self.order_alpha.mul(order))
            .add(self.address_alpha.mul(address))
            .add(self.value_alpha.mul(value))
            .add(self.action_alpha.mul(action))
            .sub(self.z);
    }

    pub fn dummy() Relation {
        return .{
            .z = QM31.fromU32Unchecked(3, 5, 7, 11),
            .clock_alpha = QM31.fromU32Unchecked(13, 17, 19, 23),
            .order_alpha = QM31.fromU32Unchecked(29, 31, 37, 41),
            .address_alpha = QM31.fromU32Unchecked(43, 47, 53, 59),
            .value_alpha = QM31.fromU32Unchecked(61, 67, 71, 73),
            .action_alpha = QM31.fromU32Unchecked(79, 83, 89, 97),
        };
    }
};

pub const Pair = struct {
    numerator: QM31,
    denominator: QM31,
};

pub const Claims = struct {
    execution: [N_EXECUTION_SUMS]QM31,
    apu: QM31,
    execution_count: usize,
    apu_count: usize,
};

/// Main-trace columns committed before lookup challenges are drawn.
pub const AuxiliaryWitness = struct {
    execution_log_size: u32,
    apu_log_size: u32,
    event_count: usize,
    execution_order_before: []M31,
    apu_mcycle: []M31,
    apu_order: []M31,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *AuxiliaryWitness) void {
        self.owned = false;
    }

    pub fn deinit(self: *AuxiliaryWitness) void {
        if (self.owned) {
            self.allocator.free(self.execution_order_before);
            self.allocator.free(self.apu_mcycle);
            self.allocator.free(self.apu_order);
        }
        self.* = undefined;
    }
};

pub const Interaction = struct {
    execution_columns: [N_EXECUTION_INTERACTION_COLUMNS][]M31,
    apu_columns: [N_APU_INTERACTION_COLUMNS][]M31,
    claims: Claims,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Interaction) void {
        for (self.execution_columns) |column| self.allocator.free(column);
        for (self.apu_columns) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateFromExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    initial_state: apu.State,
    steps: []const runner.CartridgeStepTrace,
) !ExecutionTrace {
    return generate(allocator, initial_mcycle, initial_state, steps);
}

pub fn generateFromMachineExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    initial_state: apu.State,
    results: []const scheduler_machine.CartridgeStepResult,
) !ExecutionTrace {
    return generate(allocator, initial_mcycle, initial_state, results);
}

fn generate(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    initial_state: apu.State,
    steps: anytype,
) !ExecutionTrace {
    try initial_state.validate();
    if (steps.len == 0) return error.EmptyExecutionTrace;
    var event_count: usize = 0;
    var final_mcycle = initial_mcycle;
    for (steps, 0..) |step, index| {
        try validateStepContinuity(steps, index);
        const validated = try validatedStep(step);
        for (validatedAccesses(validated)) |cycle| {
            final_mcycle = std.math.add(u32, final_mcycle, 1) catch
                return error.ApuClockOverflow;
            if (final_mcycle >= M31_MODULUS)
                return error.NonCanonicalApuClock;
            if (accessForCycle(cycle)) |access| {
                if (try eventForAccess(access) != null)
                    event_count += 1;
            }
        }
    }

    const transitions = try allocator.alloc(apu.Transition, event_count);
    errdefer allocator.free(transitions);
    const mcycles = try allocator.alloc(u32, event_count);
    errdefer allocator.free(mcycles);
    var state = initial_state;
    var at: usize = 0;
    var mcycle = initial_mcycle;
    for (steps) |step| {
        const validated = try validatedStep(step);
        for (validatedAccesses(validated)) |cycle| {
            if (accessForCycle(cycle)) |access| {
                if (try eventForAccess(access)) |event| {
                    const transition = try apu.Transition.apply(state, event);
                    if (access.action == .read and
                        transition.read_value != access.value)
                        return error.ApuReadResultMismatch;
                    transitions[at] = transition;
                    mcycles[at] = mcycle;
                    state = transition.after;
                    at += 1;
                }
            }
            mcycle += 1;
        }
    }
    std.debug.assert(at == event_count);
    var result = ExecutionTrace{
        .semantic = .{
            .rows = transitions,
            .initial_state = initial_state,
            .final_state = state,
        },
        .mcycles = mcycles,
        .final_execution_mcycle = mcycle,
    };
    errdefer result.deinit(allocator);
    try validateAgainstExecution(result, steps, initial_mcycle);
    return result;
}

pub fn validateAgainstExecution(
    trace: ExecutionTrace,
    steps: anytype,
    initial_mcycle: u32,
) !void {
    try binding.validateTrace(trace.semantic);
    if (trace.mcycles.len != trace.semantic.rows.len)
        return error.InvalidApuExecutionShape;
    if (steps.len == 0) return error.EmptyExecutionTrace;
    var state = trace.semantic.initial_state;
    var event_index: usize = 0;
    var mcycle = initial_mcycle;
    for (steps, 0..) |step, index| {
        try validateStepContinuity(steps, index);
        const validated = try validatedStep(step);
        for (validatedAccesses(validated)) |cycle| {
            if (mcycle >= M31_MODULUS)
                return error.NonCanonicalApuClock;
            if (accessForCycle(cycle)) |access| {
                if (try eventForAccess(access)) |event| {
                    if (event_index >= trace.semantic.rows.len)
                        return error.OmittedApuExecutionRow;
                    const expected = try apu.Transition.apply(state, event);
                    if (access.action == .read and
                        expected.read_value != access.value)
                        return error.ApuReadResultMismatch;
                    if (trace.mcycles[event_index] != mcycle)
                        return error.ApuExecutionClockMismatch;
                    if (!std.meta.eql(
                        trace.semantic.rows[event_index],
                        expected,
                    )) return error.SubstitutedApuExecutionRow;
                    state = expected.after;
                    event_index += 1;
                }
            }
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.ApuClockOverflow;
        }
    }
    if (event_index != trace.semantic.rows.len)
        return error.DetachedApuExecutionRow;
    if (mcycle != trace.final_execution_mcycle)
        return error.InvalidApuExecutionEndpoint;
    if (!std.meta.eql(state, trace.semantic.final_state))
        return error.InvalidApuExecutionEndpoint;
}

pub fn generateAuxiliaryWitness(
    allocator: std.mem.Allocator,
    trace: ExecutionTrace,
    steps: anytype,
    initial_mcycle: u32,
) !AuxiliaryWitness {
    try validateAgainstExecution(trace, steps, initial_mcycle);
    if (!std.math.isPowerOfTwo(steps.len))
        return error.InvalidExecutionTraceLength;
    const execution_log_size: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    const apu_size = std.math.ceilPowerOfTwo(
        usize,
        @max(trace.semantic.rows.len, 16),
    ) catch return error.ApuAccessTraceTooLong;
    const apu_log_size: u32 =
        @intCast(std.math.log2_int(usize, apu_size));
    var result = AuxiliaryWitness{
        .execution_log_size = execution_log_size,
        .apu_log_size = apu_log_size,
        .event_count = trace.semantic.rows.len,
        .execution_order_before = try allocator.alloc(M31, steps.len),
        .apu_mcycle = undefined,
        .apu_order = undefined,
        .allocator = allocator,
    };
    errdefer allocator.free(result.execution_order_before);
    result.apu_mcycle = try allocator.alloc(M31, apu_size);
    errdefer allocator.free(result.apu_mcycle);
    result.apu_order = try allocator.alloc(M31, apu_size);
    errdefer allocator.free(result.apu_order);
    @memset(result.execution_order_before, M31.zero());
    @memset(result.apu_mcycle, M31.zero());
    @memset(result.apu_order, M31.zero());

    var order: usize = 0;
    for (steps, 0..) |step, row| {
        const storage = try core_air_utils.circleBitReversedIndex(
            execution_log_size,
            row,
        );
        result.execution_order_before[storage] = try canonicalUsize(order);
        const validated = try validatedStep(step);
        for (validatedAccesses(validated)) |cycle| {
            if (accessForCycle(cycle)) |access| {
                if (try eventForAccess(access) != null)
                    order += 1;
            }
        }
    }
    if (order != trace.semantic.rows.len)
        return error.ApuExecutionCountMismatch;
    for (trace.mcycles, 0..) |clock, row| {
        const storage = try core_air_utils.circleBitReversedIndex(
            apu_log_size,
            row,
        );
        result.apu_mcycle[storage] = M31.fromCanonical(clock);
        result.apu_order[storage] = try canonicalUsize(row);
    }
    return result;
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    trace: ExecutionTrace,
    steps: anytype,
    initial_mcycle: u32,
    auxiliary: *const AuxiliaryWitness,
    relation: Relation,
) !Interaction {
    try validateAgainstExecution(trace, steps, initial_mcycle);
    if (!std.math.isPowerOfTwo(steps.len))
        return error.InvalidExecutionTraceLength;
    const apu_size = try traceSize(auxiliary.apu_log_size);
    if (auxiliary.execution_log_size !=
        std.math.log2_int(usize, steps.len) or
        auxiliary.execution_order_before.len != steps.len or
        auxiliary.event_count != trace.semantic.rows.len or
        auxiliary.apu_mcycle.len != apu_size or
        auxiliary.apu_order.len != apu_size or
        trace.semantic.rows.len > apu_size)
        return error.InvalidApuAuxiliaryShape;

    var result = Interaction{
        .execution_columns = undefined,
        .apu_columns = undefined,
        .claims = undefined,
        .allocator = allocator,
    };
    var execution_initialized: usize = 0;
    var apu_initialized: usize = 0;
    errdefer {
        for (result.execution_columns[0..execution_initialized]) |column|
            allocator.free(column);
        for (result.apu_columns[0..apu_initialized]) |column|
            allocator.free(column);
    }
    for (&result.execution_columns) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        execution_initialized += 1;
    }
    for (&result.apu_columns) |*column| {
        column.* = try allocator.alloc(M31, apu_size);
        @memset(column.*, M31.zero());
        apu_initialized += 1;
    }

    const execution_log: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    var execution_claims =
        [_]QM31{QM31.zero()} ** N_EXECUTION_SUMS;
    var execution_count: usize = 0;
    var mcycle = initial_mcycle;
    for (steps, 0..) |step, row_index| {
        const source = try stepColumns(step, mcycle);
        const machine = try liftExecution(source.execution);
        const access = try liftAccess(source.access);
        const storage = try core_air_utils.circleBitReversedIndex(
            execution_log,
            row_index,
        );
        const order_before = QM31.fromBase(
            auxiliary.execution_order_before[storage],
        );
        const pairs = executionPairs(
            machine,
            access,
            order_before,
            relation,
        );
        for (pairs, 0..) |entry, cycle| {
            execution_claims[cycle] = try accumulate(
                execution_claims[cycle],
                entry,
            );
            writeSecure(
                result.execution_columns[4 * cycle ..][0..4],
                storage,
                execution_claims[cycle],
            );
            execution_count += @intFromBool(!entry.numerator.isZero());
        }
        mcycle += stepMCycles(step);
    }

    var apu_claim = QM31.zero();
    for (0..apu_size) |row_index| {
        const storage = try core_air_utils.circleBitReversedIndex(
            auxiliary.apu_log_size,
            row_index,
        );
        const columns = if (row_index < trace.semantic.rows.len)
            try binding.columns(trace.semantic.rows[row_index])
        else
            binding.inactiveColumns();
        const row = try apuRow(QM31, &liftBinding(columns));
        const entry = apuPair(
            row,
            QM31.fromBase(auxiliary.apu_mcycle[storage]),
            QM31.fromBase(auxiliary.apu_order[storage]),
            relation,
        );
        apu_claim = try accumulate(apu_claim, entry);
        writeSecure(&result.apu_columns, storage, apu_claim);
    }
    result.claims = .{
        .execution = execution_claims,
        .apu = apu_claim,
        .execution_count = execution_count,
        .apu_count = trace.semantic.rows.len,
    };
    try verifyCancellation(
        result.claims,
        trace.semantic.initial_state,
        trace.semantic.final_state,
    );
    return result;
}

const StepColumns = struct {
    execution: [execution.N_MAIN_COLUMNS]M31,
    access: [cartridge_access_component.N_MAIN_COLUMNS]M31,
};

fn stepColumns(step: anytype, mcycle: u32) !StepColumns {
    if (comptime @TypeOf(step) == scheduler_machine.CartridgeStepResult) {
        return .{
            .execution = try execution_input.cartridgeExecutionColumns(
                try execution_input.fromCartridgeMachine(step),
                mcycle,
            ),
            .access = cartridge_machine_access.columns(
                try cartridge_machine_access.ValidatedStep.init(step),
            ),
        };
    }
    return .{
        .execution = execution.columns(step.instruction, mcycle),
        .access = try cartridge_access_component.columns(step),
    };
}

fn stepMCycles(step: anytype) u3 {
    if (comptime @TypeOf(step) == scheduler_machine.CartridgeStepResult)
        return step.m_cycles;
    return step.instruction.cycle_count;
}

pub fn executionPairs(
    machine: execution.Row(QM31),
    access: cartridge_access_component.PackedRow(QM31),
    order_before: QM31,
    relation: Relation,
) [N_EXECUTION_SUMS]Pair {
    var result: [N_EXECUTION_SUMS]Pair = undefined;
    var prefix = QM31.zero();
    for (&result, machine.bus, access.cycles, 0..) |
        *entry,
        bus,
        source,
        cycle,
    | {
        const region = source.regions[
            @intFromEnum(runner.cartridge_memory.Region.apu_mmio)
        ];
        const read = source.access_actions[
            @intFromEnum(runner.cartridge_memory.Action.read)
        ];
        const write = source.access_actions[
            @intFromEnum(runner.cartridge_memory.Action.write)
        ];
        const clock = machine.mcycle_before.add(base(@intCast(cycle)));
        const order = order_before.add(prefix);
        entry.* = pair(
            region.neg(),
            relation.combine(
                clock,
                order,
                compose(QM31, source.logical_address),
                compose(QM31, source.access_value),
                read.add(base(2).mul(write)),
            ),
        );
        prefix = prefix.add(region);
        _ = bus;
    }
    return result;
}

pub fn ApuRow(comptime S: type) type {
    return struct {
        active: S,
        read_selectors: [binding.layout.REGISTER_COUNT]S,
        write_selectors: [binding.layout.REGISTER_COUNT]S,
        write_value: [8]S,
        read_value: [8]S,
    };
}

pub fn apuRow(
    comptime S: type,
    values: []const S,
) !ApuRow(S) {
    if (values.len != binding.layout.N_MAIN_COLUMNS)
        return error.InvalidApuBindingShape;
    return .{
        .active = values[binding.layout.ACTIVE_OFFSET],
        .read_selectors = values[binding.layout.READ_ADDRESS_OFFSET..binding.layout.WRITE_ADDRESS_OFFSET].*,
        .write_selectors = values[binding.layout.WRITE_ADDRESS_OFFSET..binding.layout.WRITE_VALUE_BITS_OFFSET].*,
        .write_value = values[binding.layout.WRITE_VALUE_BITS_OFFSET..binding.layout.READ_VALUE_BITS_OFFSET].*,
        .read_value = values[binding.layout.READ_VALUE_BITS_OFFSET..binding.layout.WAVE_READ_TARGET_OFFSET].*,
    };
}

pub fn apuPair(
    row: ApuRow(QM31),
    clock: QM31,
    order: QM31,
    relation: Relation,
) Pair {
    const read = sum(QM31, &row.read_selectors);
    const write = sum(QM31, &row.write_selectors);
    const value = read.mul(compose(QM31, &row.read_value))
        .add(write.mul(compose(QM31, &row.write_value)));
    return pair(
        row.active,
        relation.combine(
            clock,
            order,
            selectedAddress(QM31, &row.read_selectors)
                .add(selectedAddress(QM31, &row.write_selectors)),
            value,
            read.add(base(2).mul(write)),
        ),
    );
}

pub fn executionSelectors(
    comptime S: type,
    access: cartridge_access_component.PackedRow(S),
) [N_EXECUTION_SUMS]S {
    var result: [N_EXECUTION_SUMS]S = undefined;
    for (&result, access.cycles) |*selector, cycle|
        selector.* = cycle.regions[
            @intFromEnum(runner.cartridge_memory.Region.apu_mmio)
        ];
    return result;
}

pub fn executionOrderConstraints(
    comptime S: type,
    current_order: S,
    next_order: S,
    selectors: [N_EXECUTION_SUMS]S,
    is_first: S,
    is_last: S,
    total: S,
) [N_EXECUTION_ORDER_CONSTRAINTS]S {
    const count = sum(S, &selectors);
    return .{
        is_first.mul(current_order),
        S.one().sub(is_last).mul(
            next_order.sub(current_order).sub(count),
        ),
        is_last.mul(current_order.add(count).sub(total)),
    };
}

pub fn apuOrderConstraints(
    comptime S: type,
    active: S,
    next_active: S,
    clock: S,
    order: S,
    next_order: S,
    is_first: S,
    is_last: S,
    total: S,
    has_events: S,
) [N_APU_ORDER_CONSTRAINTS]S {
    const one = S.one();
    const not_last = one.sub(is_last);
    return .{
        one.sub(active).mul(clock),
        one.sub(active).mul(order),
        is_first.mul(active.sub(has_events)),
        is_first.mul(order),
        not_last.mul(next_active).mul(one.sub(active)),
        not_last.mul(next_active).mul(
            next_order.sub(order).sub(one),
        ),
        active.mul(one.sub(next_active)).mul(
            order.add(one).sub(total),
        ),
        is_last.mul(active).mul(order.add(one).sub(total)),
    };
}

pub fn pairConstraint(
    comptime S: type,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    numerator: S,
    denominator: S,
) S {
    return current.sub(previous).add(is_first.mul(claim))
        .mul(denominator).sub(numerator);
}

pub fn verifyCancellation(
    claims: Claims,
    initial_state: apu.State,
    final_state: apu.State,
) !void {
    try initial_state.validate();
    try final_state.validate();
    if (claims.execution_count == 0 and claims.apu_count == 0) {
        if (!std.meta.eql(initial_state, final_state))
            return error.InvalidEmptyApuAccessEndpoint;
        if (!claims.apu.isZero())
            return error.ApuExecutionLookupSumNonZero;
        for (claims.execution) |claim|
            if (!claim.isZero())
                return error.ApuExecutionLookupSumNonZero;
        return;
    }
    if (claims.execution_count != claims.apu_count)
        return error.ApuExecutionCountMismatch;
    var total = claims.apu;
    for (claims.execution) |claim| total = total.add(claim);
    if (!total.isZero()) return error.ApuExecutionLookupSumNonZero;
}

fn eventForAccess(access: runner.cartridge_memory.Access) !?apu.Event {
    if (!apu.isAddress(access.logical_address)) {
        if (access.region == .apu_mmio)
            return error.InvalidApuMmioMetadata;
        return null;
    }
    if (access.region != .apu_mmio)
        return error.UnauthenticatedApuMmioMetadata;
    if (access.physical_offset != null)
        return error.InvalidApuMmioMetadata;
    return switch (access.action) {
        .read => .{ .read = access.logical_address },
        .write => .{ .write = .{
            .address = access.logical_address,
            .value = access.value,
        } },
    };
}

fn validatedStep(step: anytype) !if (@TypeOf(step) == scheduler_machine.CartridgeStepResult) cartridge_machine_access.ValidatedStep else cartridge_access.ValidatedStep {
    if (comptime @TypeOf(step) == scheduler_machine.CartridgeStepResult)
        return cartridge_machine_access.ValidatedStep.init(step);
    return cartridge_access.ValidatedStep.init(step);
}

fn validatedAccesses(validated: anytype) if (@TypeOf(validated) == cartridge_machine_access.ValidatedStep) []const cartridge_machine_access.Cycle else []const ?runner.cartridge_memory.Access {
    if (comptime @TypeOf(validated) == cartridge_machine_access.ValidatedStep)
        return validated.activeCycles();
    return validated.trace.activeAccesses();
}

fn accessForCycle(cycle: anytype) ?runner.cartridge_memory.Access {
    if (comptime @TypeOf(cycle) == cartridge_machine_access.Cycle)
        return cycle.access;
    return cycle;
}

fn validateStepContinuity(steps: anytype, index: usize) !void {
    if (comptime std.meta.Elem(@TypeOf(steps)) ==
        scheduler_machine.CartridgeStepResult)
    {
        if (index != 0 and !std.meta.eql(
            steps[index - 1].after,
            steps[index].before,
        )) return error.DisconnectedMachineExecution;
        if (index != 0 and !std.meta.eql(
            steps[index - 1].mapper_after,
            steps[index].mapper_before,
        )) return error.DisconnectedMapperExecution;
    }
}

fn selectedAddress(
    comptime S: type,
    selectors: *const [binding.layout.REGISTER_COUNT]S,
) S {
    var result = S.zero();
    for (selectors, 0..) |selector, register|
        result = result.add(selector.mul(
            constant(S, apu.FIRST_ADDRESS + @as(u32, @intCast(register))),
        ));
    return result;
}

fn liftExecution(
    columns: [execution.N_MAIN_COLUMNS]M31,
) !execution.Row(QM31) {
    var lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return execution.Row(QM31).fromColumns(&lifted);
}

fn liftAccess(
    columns: [cartridge_access_component.N_MAIN_COLUMNS]M31,
) !cartridge_access_component.PackedRow(QM31) {
    var lifted: [cartridge_access_component.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return cartridge_access_component.PackedRow(QM31).fromColumns(&lifted);
}

fn liftBinding(
    columns: [binding.layout.N_MAIN_COLUMNS]M31,
) [binding.layout.N_MAIN_COLUMNS]QM31 {
    var lifted: [binding.layout.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns) |*target, source|
        target.* = QM31.fromBase(source);
    return lifted;
}

fn pair(numerator: QM31, denominator: QM31) Pair {
    return .{
        .numerator = numerator,
        .denominator = if (numerator.isZero()) QM31.one() else denominator,
    };
}

fn accumulate(current: QM31, entry: Pair) !QM31 {
    return current.add(entry.numerator.mul(
        entry.denominator.inv() catch
            return error.ApuExecutionLookupZeroDenominator,
    ));
}

fn traceSize(log_size: u32) !usize {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn canonicalUsize(value: usize) !M31 {
    const narrowed = std.math.cast(u32, value) orelse
        return error.ApuExecutionCountOutsideField;
    if (narrowed >= M31_MODULUS)
        return error.ApuExecutionCountOutsideField;
    return M31.fromCanonical(narrowed);
}

fn compose(comptime S: type, bits: anytype) S {
    var result = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn sum(comptime S: type, values: anytype) S {
    var result = S.zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn constant(comptime S: type, value: u32) S {
    var result = S.zero();
    var power = S.one();
    var remaining = value;
    while (remaining != 0) : (remaining >>= 1) {
        if (remaining & 1 == 1) result = result.add(power);
        power = power.add(power);
    }
    return result;
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn writeSecure(columns: []const []M31, row: usize, value: QM31) void {
    for (columns, value.toM31Array()) |column, coordinate|
        column[row] = coordinate;
}
