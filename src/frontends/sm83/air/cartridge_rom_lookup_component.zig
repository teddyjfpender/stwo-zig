//! AIR adapter for cartridge-ROM read and public-table LogUp columns.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;
const cartridge = @import("../cartridge/mod.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");
const cartridge_access = @import("cartridge_access.zig");
const cartridge_access_component = @import("cartridge_access_component.zig");
const cartridge_rom_lookup = @import("cartridge_rom_lookup.zig");
const component_domain = @import("component_domain.zig");
const execution = @import("execution.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Kind = enum { execution, rom };
pub const N_EXECUTION_CONSTRAINTS: usize =
    cartridge_rom_lookup.N_EXECUTION_SUMS;

pub const Component = struct {
    kind: Kind,
    log_size: u32,
    is_first_column: usize,
    address_column: usize = 0,
    value_column: usize = 0,
    main_offset: usize,
    interaction_offset: usize,
    owns_execution_source: bool = true,
    relation: *const cartridge_rom_lookup.Relation,
    claims: [cartridge_rom_lookup.N_EXECUTION_SUMS]QM31,

    const Adapter = core_air_derive.ComponentAdapter(
        @This(),
        prover_component.ComponentProver,
        prover_component.Trace,
        prover_air_accumulation.DomainEvaluationAccumulator,
    );

    pub fn asVerifierComponent(self: *const @This()) core_air_components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn asProverComponent(self: *const @This()) prover_component.ComponentProver {
        return Adapter.asProverComponent(self);
    }

    pub fn nConstraints(self: *const @This()) usize {
        return switch (self.kind) {
            .execution => N_EXECUTION_CONSTRAINTS,
            .rom => 1,
        };
    }

    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }

    pub fn traceLogDegreeBounds(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) !core_air_components.TraceLogDegreeBounds {
        const preprocessed = try allocator.alloc(
            u32,
            if (self.kind == .rom) 3 else 1,
        );
        errdefer allocator.free(preprocessed);
        @memset(preprocessed, self.log_size);
        const main = try allocator.alloc(
            u32,
            self.ownedMainColumns(),
        );
        errdefer allocator.free(main);
        @memset(main, self.log_size);
        const interaction = try allocator.alloc(
            u32,
            self.interactionColumns(),
        );
        errdefer allocator.free(interaction);
        @memset(interaction, self.log_size);
        return core_air_components.TraceLogDegreeBounds.initOwned(
            try allocator.dupe([]u32, &.{ preprocessed, main, interaction }),
        );
    }

    pub fn maskPoints(
        self: *const @This(),
        allocator: std.mem.Allocator,
        point: CirclePointQM31,
        max_log_degree_bound: u32,
    ) !core_air_components.MaskPoints {
        if (max_log_degree_bound < self.log_size)
            return error.InvalidProofShape;
        const preprocessed = try component_domain.currentPointColumns(
            allocator,
            if (self.kind == .rom) 3 else 1,
            point,
        );
        errdefer component_domain.freePointColumns(allocator, preprocessed);
        const main = try component_domain.currentPointColumns(
            allocator,
            self.ownedMainColumns(),
            point,
        );
        errdefer component_domain.freePointColumns(allocator, main);
        const interaction =
            try component_domain.currentAndPreviousPointColumns(
                allocator,
                self.interactionColumns(),
                point,
                previousRowPoint(max_log_degree_bound, point),
            );
        errdefer component_domain.freePointColumns(allocator, interaction);
        return core_air_components.MaskPoints.initOwned(
            try allocator.dupe([][]CirclePointQM31, &.{
                preprocessed,
                main,
                interaction,
            }),
        );
    }

    pub fn preprocessedColumnIndices(
        self: *const @This(),
        allocator: std.mem.Allocator,
    ) ![]usize {
        return switch (self.kind) {
            .execution => allocator.dupe(usize, &.{self.is_first_column}),
            .rom => allocator.dupe(usize, &.{
                self.is_first_column,
                self.address_column,
                self.value_column,
            }),
        };
    }

    pub fn evaluateConstraintQuotientsAtPoint(
        self: *const @This(),
        point: CirclePointQM31,
        mask: *const core_air_components.MaskValues,
        accumulator: *core_air_accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) !void {
        if (max_log_degree_bound < self.log_size or mask.items.len < 3)
            return error.InvalidProofShape;
        var constraints: [N_EXECUTION_CONSTRAINTS]QM31 = undefined;
        const count = try self.evaluateSampled(
            mask.items[0],
            mask.items[1],
            mask.items[2],
            &constraints,
        );
        const inverse = try core_constraints.cosetVanishing(
            QM31,
            canonic.CanonicCoset.new(self.log_size).coset(),
            point.repeatedDouble(max_log_degree_bound - self.log_size),
        ).inv();
        for (constraints[0..count]) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(
        self: *const @This(),
        trace: *const prover_component.Trace,
        accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
    ) !void {
        if (trace.polys.items.len < 3) return error.InvalidProofShape;
        const preprocessed = trace.polys.items[0];
        const main = trace.polys.items[1];
        const interaction = trace.polys.items[2];
        if (preprocessed.len <= self.is_first_column or
            main.len < self.main_offset + self.mainColumns() or
            interaction.len <
                self.interaction_offset + self.interactionColumns())
            return error.InvalidProofShape;

        const allocator = accumulator.allocator;
        const evaluation_log_size = self.maxConstraintLogDegreeBound();
        const domain =
            canonic.CanonicCoset.new(evaluation_log_size).circleDomain();
        const evaluation_size = domain.size();
        const data_columns = if (self.kind == .execution)
            cartridge_rom_lookup.N_SOURCE_COLUMNS
        else
            3;
        const evaluations = try allocator.alloc(
            []const M31,
            1 + data_columns + self.interactionColumns(),
        );
        defer allocator.free(evaluations);
        var extension_buffers = std.ArrayList([]M31).empty;
        defer {
            for (extension_buffers.items) |values| allocator.free(values);
            extension_buffers.deinit(allocator);
        }
        evaluations[0] = try component_domain.evaluationValues(
            allocator,
            preprocessed[self.is_first_column],
            self.log_size,
            evaluation_log_size,
            evaluation_size,
            &extension_buffers,
        );
        var source: usize = 1;
        if (self.kind == .execution) {
            for (
                main[self.main_offset..][0..cartridge_rom_lookup.N_SOURCE_COLUMNS],
            ) |polynomial| {
                evaluations[source] = try component_domain.evaluationValues(
                    allocator,
                    polynomial,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
                source += 1;
            }
        } else {
            if (preprocessed.len <= self.address_column or
                preprocessed.len <= self.value_column)
                return error.InvalidProofShape;
            for ([_]prover_component.Poly{
                preprocessed[self.address_column],
                preprocessed[self.value_column],
                main[self.main_offset],
            }) |polynomial| {
                evaluations[source] = try component_domain.evaluationValues(
                    allocator,
                    polynomial,
                    self.log_size,
                    evaluation_log_size,
                    evaluation_size,
                    &extension_buffers,
                );
                source += 1;
            }
        }
        for (
            interaction[self.interaction_offset..][0..self.interactionColumns()],
        ) |polynomial| {
            evaluations[source] = try component_domain.evaluationValues(
                allocator,
                polynomial,
                self.log_size,
                evaluation_log_size,
                evaluation_size,
                &extension_buffers,
            );
            source += 1;
        }
        std.debug.assert(source == evaluations.len);
        if (extension_buffers.items.len != 0) {
            var twiddles = try prover_twiddles.precomputeM31(
                allocator,
                domain.half_coset,
            );
            defer prover_twiddles.deinitM31(allocator, &twiddles);
            try prover_poly.evaluateBuffersWithTwiddles(
                extension_buffers.items,
                domain,
                prover_twiddles.TwiddleTree([]const M31).init(
                    twiddles.root_coset,
                    twiddles.twiddles,
                    twiddles.itwiddles,
                ),
            );
        }

        const denominator_inverses =
            try component_domain.quotientDenominators(
                allocator,
                self.log_size,
                evaluation_log_size,
                domain,
            );
        defer allocator.free(denominator_inverses);
        var accumulators = try accumulator.columns(
            allocator,
            &.{.{
                .log_size = evaluation_log_size,
                .n_cols = self.nConstraints(),
            }},
        );
        defer allocator.free(accumulators);
        const column = &accumulators[0];
        const denominator_shift: std.math.Log2Int(usize) =
            @intCast(self.log_size);
        const interaction_start =
            evaluations.len - self.interactionColumns();
        for (0..evaluation_size) |row_index| {
            const previous = utils.previousBitReversedCircleDomainIndex(
                row_index,
                self.log_size,
                evaluation_log_size,
            );
            var constraints: [N_EXECUTION_CONSTRAINTS]QM31 = undefined;
            const count = try self.evaluateDomainRow(
                evaluations,
                interaction_start,
                row_index,
                previous,
                &constraints,
            );
            var folded = QM31.zero();
            for (constraints[0..count], 0..) |constraint, index| {
                const powers = column.random_coeff_powers;
                folded = folded.add(
                    powers[powers.len - 1 - index].mul(constraint),
                );
            }
            column.accumulate(
                row_index,
                folded.mulM31(
                    denominator_inverses[
                        row_index >> denominator_shift
                    ],
                ),
            );
        }
    }

    fn evaluateSampled(
        self: *const @This(),
        preprocessed: [][]QM31,
        main: [][]QM31,
        interaction: [][]QM31,
        constraints: *[N_EXECUTION_CONSTRAINTS]QM31,
    ) !usize {
        if (preprocessed.len <= self.is_first_column or
            preprocessed[self.is_first_column].len < 1)
            return error.InvalidProofShape;
        if (self.kind == .execution) {
            if (main.len <
                self.main_offset + cartridge_rom_lookup.N_SOURCE_COLUMNS)
                return error.InvalidProofShape;
            var values: [cartridge_rom_lookup.N_SOURCE_COLUMNS]QM31 =
                undefined;
            for (
                &values,
                main[self.main_offset..][0..cartridge_rom_lookup.N_SOURCE_COLUMNS],
            ) |*value, column| {
                if (column.len < 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            const row = try cartridge_rom_lookup.rowFromAccessColumns(
                QM31,
                &values,
            );
            const pairs = cartridge_rom_lookup.executionPairs(
                row,
                self.relation.*,
            );
            for (pairs, 0..) |pair, index| {
                constraints[index] =
                    cartridge_rom_lookup.pairConstraint(
                        try sampledSecure(
                            interaction,
                            self.interaction_offset + 4 * index,
                            0,
                        ),
                        try sampledSecure(
                            interaction,
                            self.interaction_offset + 4 * index,
                            1,
                        ),
                        preprocessed[self.is_first_column][0],
                        self.claims[index],
                        pair,
                    );
            }
            return N_EXECUTION_CONSTRAINTS;
        }
        if (preprocessed.len <= self.address_column or
            preprocessed.len <= self.value_column or
            main.len <= self.main_offset or
            main[self.main_offset].len < 1)
            return error.InvalidProofShape;
        constraints[0] = cartridge_rom_lookup.pairConstraint(
            try sampledSecure(
                interaction,
                self.interaction_offset,
                0,
            ),
            try sampledSecure(
                interaction,
                self.interaction_offset,
                1,
            ),
            preprocessed[self.is_first_column][0],
            self.claims[0],
            cartridge_rom_lookup.romPair(
                preprocessed[self.address_column][0],
                preprocessed[self.value_column][0],
                main[self.main_offset][0],
                self.relation.*,
            ),
        );
        return 1;
    }

    fn evaluateDomainRow(
        self: *const @This(),
        evaluations: []const []const M31,
        interaction_start: usize,
        row_index: usize,
        previous: usize,
        constraints: *[N_EXECUTION_CONSTRAINTS]QM31,
    ) !usize {
        const data_start: usize = 1;
        if (self.kind == .execution) {
            var values: [cartridge_rom_lookup.N_SOURCE_COLUMNS]QM31 =
                undefined;
            for (
                &values,
                evaluations[data_start..][0..cartridge_rom_lookup.N_SOURCE_COLUMNS],
            ) |*value, column|
                value.* = QM31.fromBase(column[row_index]);
            const source = try cartridge_rom_lookup.rowFromAccessColumns(
                QM31,
                &values,
            );
            const pairs = cartridge_rom_lookup.executionPairs(
                source,
                self.relation.*,
            );
            for (pairs, 0..) |pair, index| {
                constraints[index] =
                    cartridge_rom_lookup.pairConstraint(
                        secureAt(
                            evaluations[interaction_start + 4 * index ..][0..4],
                            row_index,
                        ),
                        secureAt(
                            evaluations[interaction_start + 4 * index ..][0..4],
                            previous,
                        ),
                        QM31.fromBase(evaluations[0][row_index]),
                        self.claims[index],
                        pair,
                    );
            }
            return N_EXECUTION_CONSTRAINTS;
        }
        constraints[0] = cartridge_rom_lookup.pairConstraint(
            secureAt(
                evaluations[interaction_start..][0..4],
                row_index,
            ),
            secureAt(
                evaluations[interaction_start..][0..4],
                previous,
            ),
            QM31.fromBase(evaluations[0][row_index]),
            self.claims[0],
            cartridge_rom_lookup.romPair(
                QM31.fromBase(evaluations[data_start][row_index]),
                QM31.fromBase(evaluations[data_start + 1][row_index]),
                QM31.fromBase(evaluations[data_start + 2][row_index]),
                self.relation.*,
            ),
        );
        return 1;
    }

    fn mainColumns(self: *const @This()) usize {
        return if (self.kind == .rom)
            1
        else
            cartridge_rom_lookup.N_SOURCE_COLUMNS;
    }

    fn ownedMainColumns(self: *const @This()) usize {
        if (self.kind == .execution and !self.owns_execution_source)
            return 0;
        return self.mainColumns();
    }

    fn interactionColumns(self: *const @This()) usize {
        return switch (self.kind) {
            .execution => cartridge_rom_lookup.N_EXECUTION_COLUMNS,
            .rom => cartridge_rom_lookup.N_ROM_COLUMNS,
        };
    }
};

fn previousRowPoint(log_size: u32, point: CirclePointQM31) CirclePointQM31 {
    const step = canonic.CanonicCoset.new(log_size).coset_value.step;
    return point.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
}

fn sampledSecure(
    columns: [][]QM31,
    offset: usize,
    point: usize,
) !QM31 {
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, 0..) |*coordinate, index| {
        if (columns.len <= offset + index or
            columns[offset + index].len <= point)
            return error.InvalidProofShape;
        coordinate.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

test "cartridge ROM lookup component owns execution and public table domains" {
    const relation = cartridge_rom_lookup.Relation.dummy();
    const execution_component = Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** cartridge_rom_lookup.N_EXECUTION_SUMS,
    };
    const rom = Component{
        .kind = .rom,
        .log_size = cartridge_rom_lookup.ROM_LOG_SIZE,
        .is_first_column = 0,
        .address_column = 1,
        .value_column = 2,
        .main_offset = cartridge_rom_lookup.N_SOURCE_COLUMNS,
        .interaction_offset = cartridge_rom_lookup.N_EXECUTION_COLUMNS,
        .relation = &relation,
        .claims = .{QM31.zero()} ** cartridge_rom_lookup.N_EXECUTION_SUMS,
    };
    try std.testing.expectEqual(
        N_EXECUTION_CONSTRAINTS,
        execution_component.nConstraints(),
    );
    try std.testing.expectEqual(@as(usize, 1), rom.nConstraints());
    _ = execution_component.asVerifierComponent();
    _ = rom.asProverComponent();
}

test "cartridge ROM execution domain rejects offset byte and activity mutations" {
    const allocator = std.testing.allocator;
    const relation = cartridge_rom_lookup.Relation.dummy();
    var component = Component{
        .kind = .execution,
        .log_size = 4,
        .is_first_column = 0,
        .main_offset = 0,
        .interaction_offset = 0,
        .relation = &relation,
        .claims = .{QM31.zero()} ** cartridge_rom_lookup.N_EXECUTION_SUMS,
    };
    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 1 << evaluation_log_size;
    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var preprocessed = [_]prover_component.Poly{.{
        .log_size = evaluation_log_size,
        .values = &first_values,
    }};
    const access_trace = try syntheticAccess(
        .{ .rom_bank_register = 2 },
    );
    const access_witness =
        try cartridge_access_component.columns(access_trace);
    var main_values: [cartridge_rom_lookup.N_SOURCE_COLUMNS][evaluation_size]M31 =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** cartridge_rom_lookup.N_SOURCE_COLUMNS;
    for (&main_values, access_witness) |*values, value|
        @memset(values, value);
    const offset: u20 = 0x8000;
    const byte: u8 = 0x42;
    var main: [cartridge_rom_lookup.N_SOURCE_COLUMNS]prover_component.Poly =
        undefined;
    for (&main, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var interaction_values: [cartridge_rom_lookup.N_EXECUTION_COLUMNS][evaluation_size]M31 =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** cartridge_rom_lookup.N_EXECUTION_COLUMNS;
    const denominator = relation.combine(
        QM31.fromBase(M31.fromCanonical(offset)),
        QM31.fromBase(M31.fromCanonical(byte)),
    );
    const increment = QM31.one().neg().mul(try denominator.inv());
    var next: [evaluation_size]usize = undefined;
    for (0..evaluation_size) |row_index| {
        const previous = utils.previousBitReversedCircleDomainIndex(
            row_index,
            component.log_size,
            evaluation_log_size,
        );
        next[previous] = row_index;
    }
    var visited = [_]bool{false} ** evaluation_size;
    var accumulators = [_]QM31{QM31.zero()} ** evaluation_size;
    var cycle_size: usize = 0;
    for (0..evaluation_size) |start| {
        if (visited[start]) continue;
        first_values[start] = M31.one();
        visited[start] = true;
        var current = start;
        var length: usize = 1;
        while (next[current] != start) {
            const following = next[current];
            accumulators[following] =
                accumulators[current].add(increment);
            visited[following] = true;
            current = following;
            length += 1;
        }
        if (cycle_size == 0)
            cycle_size = length
        else
            try std.testing.expectEqual(cycle_size, length);
    }
    component.claims[0] = increment.mul(
        QM31.fromBase(M31.fromCanonical(@intCast(cycle_size))),
    );
    for (accumulators, 0..) |value, row_index| {
        const coordinates = value.toM31Array();
        for (coordinates, 0..) |coordinate, column|
            interaction_values[column][row_index] = coordinate;
    }
    var interaction: [cartridge_rom_lookup.N_EXECUTION_COLUMNS]prover_component.Poly =
        undefined;
    for (&interaction, &interaction_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = @import("stwo_core").pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);

    try expectDomainZero(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );
    const offset_bit = cartridge_access.PHYSICAL_OFFSET + 15;
    @memset(&main_values[offset_bit], M31.zero());
    try expectDomainZero(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&main_values[offset_bit], M31.one());

    const byte_bit = cartridge_access.ACCESS_VALUE_OFFSET;
    @memset(&main_values[byte_bit], M31.one());
    try expectDomainZero(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&main_values[byte_bit], M31.zero());

    const active_column = cartridge_access.REGION_OFFSET +
        @intFromEnum(runner.cartridge_memory.Region.cartridge_rom);
    @memset(&main_values[active_column], M31.zero());
    try expectDomainZero(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

test "packed access binding rejects a different valid ROM source" {
    const allocator = std.testing.allocator;
    const rom = try allocator.alloc(u8, cartridge_rom_lookup.ROM_SIZE);
    defer allocator.free(rom);
    @memset(rom, 0);
    rom[0x4000] = 0x42;
    rom[0x8000] = 0x42;
    const bank_one = cartridge.mbc3.State{ .rom_bank_register = 1 };
    const honest = try syntheticAccess(bank_one);
    const forged = try syntheticAccess(
        .{ .rom_bank_register = 2 },
    );
    const honest_steps = [_]runner.CartridgeStepTrace{honest} ** 16;
    const forged_steps = [_]runner.CartridgeStepTrace{forged} ** 16;
    var honest_lookup = try cartridge_rom_lookup.generate(
        allocator,
        &honest_steps,
        rom,
        cartridge_rom_lookup.Relation.dummy(),
    );
    defer honest_lookup.deinit();
    try cartridge_rom_lookup.verifyCancellation(honest_lookup.claims);
    var forged_lookup = try cartridge_rom_lookup.generate(
        allocator,
        &forged_steps,
        rom,
        cartridge_rom_lookup.Relation.dummy(),
    );
    defer forged_lookup.deinit();
    try cartridge_rom_lookup.verifyCancellation(forged_lookup.claims);

    const access_component = cartridge_access_component.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .execution_offset = 0,
        .main_offset = execution.N_MAIN_COLUMNS,
        .initial = bank_one,
        .final = bank_one,
    };
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine, execution.columns(honest.instruction, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    var honest_access: [cartridge_access_component.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &honest_access,
        try cartridge_access_component.columns(honest),
    ) |*value, source| value.* = QM31.fromBase(source);
    try std.testing.expect(
        (try access_component.evaluateRow(
            &machine,
            &honest_access,
            &honest_access,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );
    var forged_access: [cartridge_access_component.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &forged_access,
        try cartridge_access_component.columns(forged),
    ) |*value, source| value.* = QM31.fromBase(source);
    try std.testing.expect(
        !(try access_component.evaluateRow(
            &machine,
            &forged_access,
            &forged_access,
            QM31.one(),
            QM31.one(),
        )).allZero(),
    );
}

fn syntheticAccess(
    mapper: cartridge.mbc3.State,
) !runner.CartridgeStepTrace {
    const offset: runner.cartridge_memory.PhysicalOffset =
        @as(runner.cartridge_memory.PhysicalOffset, mapper.selectedRomBank()) *
        @as(
            runner.cartridge_memory.PhysicalOffset,
            cartridge.header.ROM_BANK_SIZE,
        );
    var trace: runner.CartridgeStepTrace = undefined;
    trace.instruction.before = .{};
    trace.instruction.after = .{ .pc = 1 };
    trace.instruction.decoded = try isa.decode(&.{0x42});
    trace.instruction.cycle_count = 1;
    trace.instruction.branch_taken = false;
    trace.instruction.result = null;
    trace.instruction.cycles[0] = .{
        .address = 0x4000,
        .value = 0x42,
        .action = .read,
    };
    trace.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    trace.accesses[0] = .{
        .logical_address = 0x4000,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = offset,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = 0x42,
    };
    return trace;
}

fn expectDomainZero(
    allocator: std.mem.Allocator,
    component: *const Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected_zero: bool,
) !void {
    var accumulator =
        try prover_air_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            challenge,
            evaluation_log_size,
            component.nConstraints(),
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    var all_zero = true;
    for (0..result.len()) |row|
        all_zero = all_zero and result.at(row).isZero();
    try std.testing.expectEqual(expected_zero, all_zero);
}
