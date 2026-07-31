const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const binding = @import("apu_binding.zig");
const cartridge_access = @import("cartridge_access_component.zig");
const execution = @import("execution.zig");
const lookup = @import("apu_execution_lookup.zig");
const subject = @import("apu_execution_lookup_component.zig");
const apu = @import("../runner/apu_mmio.zig");
const runner = @import("../runner/mod.zig");
const memory = runner.cartridge_memory;

test "APU execution lookup components expose backend-generic cubic shapes" {
    const relation = lookup.Relation.dummy();
    const claims = emptyClaims();
    const execution_component = subject.Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 1,
        .is_last_column = 3,
        .execution_offset = 2,
        .access_offset = 2 + execution.N_MAIN_COLUMNS,
        .auxiliary_offset = 2 + execution.N_MAIN_COLUMNS +
            cartridge_access.N_MAIN_COLUMNS,
        .interaction_offset = 5,
        .relation = &relation,
        .claims = claims,
    };
    try std.testing.expectEqual(
        lookup.N_EXECUTION_CONSTRAINTS,
        execution_component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        execution_component.maxConstraintLogDegreeBound(),
    );
    _ = execution_component.asVerifierComponent();
    _ = execution_component.asProverComponent();
    var execution_bounds = try execution_component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer execution_bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), execution_bounds.items.len);

    const apu_component = subject.Component{
        .kind = .apu,
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .binding_offset = 3,
        .auxiliary_offset = 3 + binding.layout.N_MAIN_COLUMNS,
        .interaction_offset = 7,
        .relation = &relation,
        .claims = claims,
    };
    try std.testing.expectEqual(
        lookup.N_APU_CONSTRAINTS,
        apu_component.nConstraints(),
    );
    _ = apu_component.asVerifierComponent();
    _ = apu_component.asProverComponent();
    var apu_bounds = try apu_component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer apu_bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), apu_bounds.items.len);
}

test "APU lookup components reject clock order ownership and vacuity mutations" {
    const allocator = std.testing.allocator;
    const steps = scenarioSteps();
    var trace = try lookup.generateFromExecution(allocator, 0, .{}, &steps);
    defer trace.deinit(allocator);
    var auxiliary = try lookup.generateAuxiliaryWitness(
        allocator,
        trace,
        &steps,
        0,
    );
    defer auxiliary.deinit();
    const relation = lookup.Relation.dummy();
    var interaction = try lookup.generateInteraction(
        allocator,
        trace,
        &steps,
        0,
        &auxiliary,
        relation,
    );
    defer interaction.deinit();

    var execution_component = subject.Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .access_offset = execution.N_MAIN_COLUMNS,
        .auxiliary_offset = execution.N_MAIN_COLUMNS +
            cartridge_access.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = interaction.claims,
    };
    const execution_main_len = execution_component.auxiliary_offset + 1;
    const execution_current = try allocator.alloc(M31, execution_main_len);
    defer allocator.free(execution_current);
    const execution_next = try allocator.alloc(M31, execution_main_len);
    defer allocator.free(execution_next);
    @memset(execution_current, M31.zero());
    @memset(execution_next, M31.zero());
    const first_execution = execution.columns(steps[0].instruction, 0);
    const next_execution = execution.columns(steps[1].instruction, 1);
    @memcpy(
        execution_current[0..execution.N_MAIN_COLUMNS],
        &first_execution,
    );
    @memcpy(
        execution_next[0..execution.N_MAIN_COLUMNS],
        &next_execution,
    );
    const first_access = try cartridge_access.columns(steps[0]);
    const next_access = try cartridge_access.columns(steps[1]);
    @memcpy(
        execution_current[execution_component.access_offset..][0..cartridge_access.N_MAIN_COLUMNS],
        &first_access,
    );
    @memcpy(
        execution_next[execution_component.access_offset..][0..cartridge_access.N_MAIN_COLUMNS],
        &next_access,
    );
    const first_execution_storage = try core.air.utils
        .circleBitReversedIndex(4, 0);
    const next_execution_storage = try core.air.utils
        .circleBitReversedIndex(4, 1);
    execution_current[execution_component.auxiliary_offset] =
        auxiliary.execution_order_before[first_execution_storage];
    execution_next[execution_component.auxiliary_offset] =
        auxiliary.execution_order_before[next_execution_storage];
    var execution_main = try sampledMain(
        allocator,
        execution_current,
        execution_next,
    );
    defer freeSampled(allocator, execution_main);
    var execution_interaction = try sampledInteraction(
        allocator,
        &interaction.execution_columns,
        first_execution_storage,
        &interaction.claims.execution,
    );
    defer freeSampled(allocator, execution_interaction);
    var first_storage = [_]QM31{QM31.one()};
    var last_storage = [_]QM31{QM31.zero()};
    var preprocessed = [_][]QM31{ &first_storage, &last_storage };
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    var count = try execution_component.evaluateSampled(
        &preprocessed,
        execution_main,
        execution_interaction,
        &constraints,
    );
    try expectZero(constraints[0..count]);

    execution_main[execution_component.auxiliary_offset][0] = QM31.one();
    count = try execution_component.evaluateSampled(
        &preprocessed,
        execution_main,
        execution_interaction,
        &constraints,
    );
    try expectNonZero(constraints[0..count]);
    execution_main[execution_component.auxiliary_offset][0] = QM31.zero();
    execution_interaction[0][0] = execution_interaction[0][0].add(QM31.one());
    count = try execution_component.evaluateSampled(
        &preprocessed,
        execution_main,
        execution_interaction,
        &constraints,
    );
    try expectNonZero(constraints[0..count]);
    execution_interaction[0][0] = execution_interaction[0][0].sub(QM31.one());

    var apu_component = subject.Component{
        .kind = .apu,
        .log_size = auxiliary.apu_log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .binding_offset = 0,
        .auxiliary_offset = binding.layout.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = interaction.claims,
    };
    const apu_main_len = apu_component.auxiliary_offset + 2;
    const apu_current = try allocator.alloc(M31, apu_main_len);
    defer allocator.free(apu_current);
    const apu_next = try allocator.alloc(M31, apu_main_len);
    defer allocator.free(apu_next);
    @memset(apu_current, M31.zero());
    @memset(apu_next, M31.zero());
    const first_binding = try binding.columns(trace.semantic.rows[0]);
    const next_binding = try binding.columns(trace.semantic.rows[1]);
    @memcpy(apu_current[0..binding.layout.N_MAIN_COLUMNS], &first_binding);
    @memcpy(apu_next[0..binding.layout.N_MAIN_COLUMNS], &next_binding);
    const first_apu_storage = try core.air.utils.circleBitReversedIndex(4, 0);
    const next_apu_storage = try core.air.utils.circleBitReversedIndex(4, 1);
    apu_current[apu_component.auxiliary_offset] =
        auxiliary.apu_mcycle[first_apu_storage];
    apu_next[apu_component.auxiliary_offset] =
        auxiliary.apu_mcycle[next_apu_storage];
    apu_current[apu_component.auxiliary_offset + 1] =
        auxiliary.apu_order[first_apu_storage];
    apu_next[apu_component.auxiliary_offset + 1] =
        auxiliary.apu_order[next_apu_storage];
    var apu_main = try sampledMain(allocator, apu_current, apu_next);
    defer freeSampled(allocator, apu_main);
    const apu_interaction = try sampledInteraction(
        allocator,
        &interaction.apu_columns,
        first_apu_storage,
        &.{interaction.claims.apu},
    );
    defer freeSampled(allocator, apu_interaction);
    count = try apu_component.evaluateSampled(
        &preprocessed,
        apu_main,
        apu_interaction,
        &constraints,
    );
    try expectZero(constraints[0..count]);

    apu_main[apu_component.auxiliary_offset][0] = QM31.one();
    count = try apu_component.evaluateSampled(
        &preprocessed,
        apu_main,
        apu_interaction,
        &constraints,
    );
    try expectNonZero(constraints[0..count]);
    apu_main[apu_component.auxiliary_offset][0] = QM31.zero();
    apu_main[binding.layout.ACTIVE_OFFSET][0] = QM31.zero();
    count = try apu_component.evaluateSampled(
        &preprocessed,
        apu_main,
        apu_interaction,
        &constraints,
    );
    try expectNonZero(constraints[0..count]);
}

test "APU lookup components admit only honest zero-event witnesses" {
    const allocator = std.testing.allocator;
    const relation = lookup.Relation.dummy();
    const claims = emptyClaims();
    const component = subject.Component{
        .kind = .apu,
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .binding_offset = 0,
        .auxiliary_offset = binding.layout.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = claims,
    };
    const main_len = component.auxiliary_offset + 2;
    const current = try allocator.alloc(M31, main_len);
    defer allocator.free(current);
    const next = try allocator.alloc(M31, main_len);
    defer allocator.free(next);
    @memset(current, M31.zero());
    @memset(next, M31.zero());
    var main = try sampledMain(allocator, current, next);
    defer freeSampled(allocator, main);
    var zero_0 = [_]M31{M31.zero()};
    var zero_1 = [_]M31{M31.zero()};
    var zero_2 = [_]M31{M31.zero()};
    var zero_3 = [_]M31{M31.zero()};
    var interaction_columns = [_][]M31{
        &zero_0,
        &zero_1,
        &zero_2,
        &zero_3,
    };
    const interaction = try sampledInteraction(
        allocator,
        &interaction_columns,
        0,
        &.{QM31.zero()},
    );
    defer freeSampled(allocator, interaction);
    var first_storage = [_]QM31{QM31.one()};
    var last_storage = [_]QM31{QM31.zero()};
    var preprocessed = [_][]QM31{ &first_storage, &last_storage };
    var constraints: [subject.N_MAX_CONSTRAINTS]QM31 = undefined;
    var count = try component.evaluateSampled(
        &preprocessed,
        main,
        interaction,
        &constraints,
    );
    try expectZero(constraints[0..count]);
    main[component.auxiliary_offset][0] = QM31.one();
    count = try component.evaluateSampled(
        &preprocessed,
        main,
        interaction,
        &constraints,
    );
    try expectNonZero(constraints[0..count]);
}

test "execution component admits multiple APU accesses per instruction row" {
    const allocator = std.testing.allocator;
    const steps = [_]runner.CartridgeStepTrace{multiAccessStep()} ** 16;
    var trace = try lookup.generateFromExecution(allocator, 0, .{}, &steps);
    defer trace.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 32), trace.semantic.rows.len);
    var auxiliary = try lookup.generateAuxiliaryWitness(
        allocator,
        trace,
        &steps,
        0,
    );
    defer auxiliary.deinit();
    const relation = lookup.Relation.dummy();
    var interaction = try lookup.generateInteraction(
        allocator,
        trace,
        &steps,
        0,
        &auxiliary,
        relation,
    );
    defer interaction.deinit();
    try std.testing.expectEqual(@as(u32, 4), auxiliary.execution_log_size);
    try std.testing.expectEqual(@as(u32, 5), auxiliary.apu_log_size);
    const execution_component = subject.Component{
        .kind = .execution,
        .log_size = auxiliary.execution_log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .access_offset = execution.N_MAIN_COLUMNS,
        .auxiliary_offset = execution.N_MAIN_COLUMNS +
            cartridge_access.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = interaction.claims,
    };
    var execution_bounds = try execution_component.traceLogDegreeBounds(
        allocator,
    );
    defer execution_bounds.deinitDeep(allocator);
    const apu_component = subject.Component{
        .kind = .apu,
        .log_size = auxiliary.apu_log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .binding_offset = 0,
        .auxiliary_offset = binding.layout.N_MAIN_COLUMNS,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = interaction.claims,
    };
    var apu_bounds = try apu_component.traceLogDegreeBounds(allocator);
    defer apu_bounds.deinitDeep(allocator);
}

fn scenarioSteps() [16]runner.CartridgeStepTrace {
    var result = [_]runner.CartridgeStepTrace{
        accessStep(0xff80, .read, 0, .system),
    } ** 16;
    result[0] = accessStep(apu.NR52, .write, 0x80, .apu_mmio);
    result[2] = accessStep(0xff12, .write, 0x71, .apu_mmio);
    return result;
}

fn accessStep(
    address: u16,
    action: memory.Action,
    value: u8,
    region: memory.Region,
) runner.CartridgeStepTrace {
    var result: runner.CartridgeStepTrace = undefined;
    result.instruction.cycle_count = 1;
    result.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    result.accesses = [_]?memory.Access{null} ** runner.MAX_BUS_CYCLES;
    result.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
    return result;
}

fn multiAccessStep() runner.CartridgeStepTrace {
    var result: runner.CartridgeStepTrace = undefined;
    result.instruction.cycle_count = 2;
    result.accesses = [_]?memory.Access{null} ** runner.MAX_BUS_CYCLES;
    const addresses = [_]u16{ 0xff24, 0xff25 };
    for (addresses, 0..) |address, cycle| {
        result.instruction.cycles[cycle] = .{
            .address = address,
            .value = 0,
            .action = .read,
        };
        result.accesses[cycle] = .{
            .logical_address = address,
            .action = .read,
            .region = .apu_mmio,
            .physical_offset = null,
            .mapper_before = .{},
            .mapper_after = .{},
            .value = 0,
        };
    }
    return result;
}

fn sampledMain(
    allocator: std.mem.Allocator,
    current: []const M31,
    next: []const M31,
) ![][]QM31 {
    if (current.len != next.len) return error.InvalidTestShape;
    const result = try allocator.alloc([]QM31, current.len);
    errdefer allocator.free(result);
    var initialized: usize = 0;
    errdefer for (result[0..initialized]) |column| allocator.free(column);
    for (result, current, next) |*column, current_value, next_value| {
        column.* = try allocator.alloc(QM31, 2);
        column.*[0] = QM31.fromBase(current_value);
        column.*[1] = QM31.fromBase(next_value);
        initialized += 1;
    }
    return result;
}

fn sampledInteraction(
    allocator: std.mem.Allocator,
    columns: []const []M31,
    storage: usize,
    claims: []const QM31,
) ![][]QM31 {
    const result = try allocator.alloc([]QM31, columns.len);
    errdefer allocator.free(result);
    var initialized: usize = 0;
    errdefer for (result[0..initialized]) |column| allocator.free(column);
    for (result, columns, 0..) |*column, source, index| {
        column.* = try allocator.alloc(QM31, 2);
        column.*[0] = QM31.fromBase(source[storage]);
        const coordinates = claims[index / 4].toM31Array();
        column.*[1] = QM31.fromBase(coordinates[index % 4]);
        initialized += 1;
    }
    return result;
}

fn freeSampled(allocator: std.mem.Allocator, columns: [][]QM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn expectZero(constraints: []const QM31) !void {
    for (constraints) |constraint| try std.testing.expect(constraint.isZero());
}

fn expectNonZero(constraints: []const QM31) !void {
    for (constraints) |constraint|
        if (!constraint.isZero()) return;
    return error.ExpectedMutationRejection;
}

fn emptyClaims() lookup.Claims {
    return .{
        .execution = [_]QM31{QM31.zero()} ** lookup.N_EXECUTION_SUMS,
        .apu = QM31.zero(),
        .execution_count = 0,
        .apu_count = 0,
    };
}
