const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const prover_task_graph = prover_engine.task_graph;
const prover_work_pool = prover_engine.work_pool;
const ClockUpdateComponent = @import("clock_update_component.zig").ClockUpdateComponent;
const interaction = @import("clock_update_interaction.zig");
const infra = @import("../infra_trace.zig");
const access_witness = @import("../runner/access_witness.zig");
const DecodedInst = @import("../runner/decode.zig").DecodedInst;
const state_chain = @import("../runner/state_chain.zig");
const counter = @import("lookups/tables/counter.zig");
const relations_mod = @import("relation_challenges.zig");

const TestMain = struct {
    columns: [interaction.N_MAIN_COLUMNS][]M31,

    fn deinit(self: *TestMain, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column);
        self.* = undefined;
    }
};

fn testMain(allocator: std.mem.Allocator, log_size: u32) !TestMain {
    const size = @as(usize, 1) << @intCast(log_size);
    var result: TestMain = undefined;
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column| allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const row = placement.map(0);
    const values = [_]u32{ 1, 1, 0x1000, 7, 0x11, 0x22, 0x33, 0x44, 7, 0 };
    for (&result.columns, values) |column, value| column[row] = M31.fromU64(value);
    return result;
}

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

fn rowForClockUpdate(update: state_chain.ClockUpdate) interaction.Row {
    const value_limbs = update.valueLimbs();
    return .{
        .enabler = QM31.one(),
        .addr_space = q(update.addr_space),
        .addr = q(update.addr),
        .clock_prev = q(update.clk_prev),
        .value = .{
            QM31.fromBase(value_limbs[0]),
            QM31.fromBase(value_limbs[1]),
            QM31.fromBase(value_limbs[2]),
            QM31.fromBase(value_limbs[3]),
        },
        .clock_prev_low20 = q(update.clk_prev & ((@as(u32, 1) << 20) - 1)),
        .clock_prev_high6 = q(update.clk_prev >> 20),
    };
}

fn expectMemoryTuple(
    relation_entry: @import("lookups/entry.zig").Entry,
    addr_space: u32,
    addr: u32,
    clock: u32,
    value_limbs: [4]M31,
) !void {
    try std.testing.expectEqual(
        @import("lookups/entry.zig").Domain.memory_access,
        relation_entry.domain,
    );
    try std.testing.expectEqual(@as(u8, 7), relation_entry.arity);
    try std.testing.expect(relation_entry.values[0].eql(q(addr_space)));
    try std.testing.expect(relation_entry.values[1].eql(q(addr)));
    try std.testing.expect(relation_entry.values[2].eql(q(clock)));
    for (value_limbs, relation_entry.values[3..7]) |limb, actual| {
        try std.testing.expect(actual.eql(QM31.fromBase(limb)));
    }
}

fn expectSameMemoryTuple(
    lhs: @import("lookups/entry.zig").Entry,
    rhs: @import("lookups/entry.zig").Entry,
) !void {
    try std.testing.expectEqual(lhs.domain, rhs.domain);
    try std.testing.expectEqual(lhs.arity, rhs.arity);
    for (lhs.values[0..lhs.arity], rhs.values[0..rhs.arity]) |left, right| {
        try std.testing.expect(left.eql(right));
    }
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

fn testLeafTaskContext(
    user_context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = user_context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

fn runPreparedOnBoundedHelper(
    prepared: *prepared_domain.PreparedDomainEvaluation,
) !void {
    const Runner = struct {
        prepared: *prepared_domain.PreparedDomainEvaluation,
        coordinator_thread: std.Thread.Id,
        ran_on_helper: std.atomic.Value(bool) = .init(false),

        fn run(context: *prover_task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            if (std.Thread.getCurrentId() == self.coordinator_thread) {
                return error.PreparedDomainDidNotUseHelper;
            }
            self.ran_on_helper.store(true, .release);
            try self.prepared.run(context);
        }
    };
    const Coordinator = struct {
        fn run(_: *prover_task_graph.TaskContext) !void {}
    };

    var runner = Runner{
        .prepared = prepared,
        .coordinator_thread = std.Thread.getCurrentId(),
    };
    var coordinator_byte: u8 = 0;
    var graph = try prover_task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        2,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .name = "clock-stack-probe-coordinator",
        .func = Coordinator.run,
        .context = &coordinator_byte,
        .work_estimate = 2,
    });
    _ = try graph.addTask(.{
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 1,
            .shard_or_chunk_index = 0,
        },
        .name = "clock-stack-probe-prepared",
        .func = Runner.run,
        .context = &runner,
        .resources = prepared.resources,
        .work_estimate = 1,
    });

    var pool: prover_work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
    });
    defer pool.deinit();
    _ = try graph.execute(.{
        .worker_budget = try prover_work_pool.WorkerBudget.init(2),
        .pool = &pool,
    });
    try std.testing.expect(runner.ran_on_helper.load(.acquire));
}

fn prepareClockUpdateDomain(
    allocator: std.mem.Allocator,
    component: *const ClockUpdateComponent,
    trace_data: *const prover_component.Trace,
    eval_log_size: u32,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
}

test "clock update exposes the exact memory pair and bounds its predecessor clock" {
    const row = try interaction.Row.fromMain(&.{
        QM31.one(), q(1), q(0x1000), q(7), q(0x11), q(0x22), q(0x33), q(0x44),
        q(7),       q(0),
    });
    const entries = interaction.orderedEntries(row);
    try std.testing.expectEqual(@as(usize, 4), entries.len);
    try std.testing.expectEqual(@as(usize, 2), entries.batchCount());
    try std.testing.expectEqual(@as(usize, 1), interaction.RANGE_CHECK_20_ENTRIES_PER_ROW);
    try std.testing.expectEqual(@as(usize, 1), interaction.RANGE_CHECK_8_8_ENTRIES_PER_ROW);
    try std.testing.expectEqual(@import("lookups/entry.zig").Domain.memory_access, entries.entries[0].domain);
    try std.testing.expectEqual(@import("lookups/entry.zig").Domain.memory_access, entries.entries[1].domain);
    try std.testing.expectEqual(@import("lookups/entry.zig").Domain.range_check_20, entries.entries[2].domain);
    try std.testing.expectEqual(@import("lookups/entry.zig").Domain.range_check_8_8, entries.entries[3].domain);
    try std.testing.expect(entries.entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries.entries[1].numerator.eql(QM31.one()));
    try std.testing.expect(entries.entries[2].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries.entries[3].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries.entries[0].values[2].eql(q(7)));
    try std.testing.expect(entries.entries[1].values[2].eql(
        q(7 + state_chain.MAX_CLOCK_DIFF),
    ));
    try std.testing.expect(entries.entries[2].values[0].eql(q(7)));
    try std.testing.expect(entries.entries[3].values[0].eql(q(0)));
    try std.testing.expect(entries.entries[3].values[1].eql(q(0)));

    const allocator = std.testing.allocator;
    var counters = try counter.Set.init(allocator);
    defer counters.deinit(allocator);
    try counters.registerList(entries);
    try std.testing.expect(counters.get(.range_check_20).signedTotal().eql(M31.one().neg()));
    try std.testing.expect(counters.get(.range_check_8_8).signedTotal().eql(M31.one().neg()));
}

test "clock update predecessor bound cuts the shortest wrapped M31 clock cycle" {
    const modulus: u64 = m31.Modulus;
    const gap: u64 = state_chain.MAX_CLOCK_DIFF;
    const start: u64 = 1;
    const update_count: usize = 2048;

    // Before the bound, 2,048 synthetic +MAX edges and one otherwise-valid
    // opcode access of gap 2,047 form a detached memory-bus cycle:
    //
    //   1 --(+MAX)^2048--> p - 2046 --(+2047 mod p)--> 1.
    //
    // Count the endpoints directly; values/address are held identical, so
    // equality of the clock coordinate is equality of the complete tuple.
    var multiplicity = std.AutoHashMap(u32, i32).init(std.testing.allocator);
    defer multiplicity.deinit();
    for (0..update_count) |index| {
        const previous = start + @as(u64, index) * gap;
        const next = previous + gap;
        try std.testing.expect(next < modulus);
        const previous_entry = try multiplicity.getOrPut(@intCast(previous));
        if (!previous_entry.found_existing) previous_entry.value_ptr.* = 0;
        previous_entry.value_ptr.* -= 1;
        const next_entry = try multiplicity.getOrPut(@intCast(next));
        if (!next_entry.found_existing) next_entry.value_ptr.* = 0;
        next_entry.value_ptr.* += 1;
    }
    const wrapped_previous = start + @as(u64, update_count) * gap;
    try std.testing.expectEqual(modulus - 2046, wrapped_previous);
    try std.testing.expectEqual(
        @as(u64, 2047),
        (start + modulus - wrapped_previous) % modulus,
    );
    const tail = try multiplicity.getOrPut(@intCast(wrapped_previous));
    if (!tail.found_existing) tail.value_ptr.* = 0;
    tail.value_ptr.* -= 1;
    const head = try multiplicity.getOrPut(@intCast(start));
    if (!head.found_existing) head.value_ptr.* = 0;
    head.value_ptr.* += 1;
    var values = multiplicity.valueIterator();
    while (values.next()) |value| try std.testing.expectEqual(@as(i32, 0), value.*);

    // Recomposition can represent that late predecessor only with a high limb
    // outside the six-bit protocol window. The exact source-counter path therefore
    // rejects the row before it can enter a proof.
    const dangerous_update_prev = start + @as(u64, update_count - 1) * gap;
    const low20: u32 = @intCast(dangerous_update_prev & ((1 << 20) - 1));
    const high: u32 = @intCast(dangerous_update_prev >> 20);
    try std.testing.expect(high >= 64);
    const forged = interaction.Row{
        .enabler = QM31.one(),
        .addr_space = QM31.zero(),
        .addr = q(1),
        .clock_prev = q(@intCast(dangerous_update_prev)),
        .value = .{QM31.zero()} ** 4,
        .clock_prev_low20 = q(low20),
        .clock_prev_high6 = q(high),
    };
    var counters = try counter.Set.init(std.testing.allocator);
    defer counters.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.ValueOutOfRange,
        counters.registerList(interaction.orderedEntries(forged)),
    );
}

test "clock predecessor range sources come from the exact committed columns" {
    const allocator = std.testing.allocator;
    var main = try testMain(allocator, 4);
    defer main.deinit(allocator);
    var views: [interaction.N_MAIN_COLUMNS][]const M31 = undefined;
    for (&views, &main.columns) |*view, column| view.* = column;

    var counters = try counter.Set.init(allocator);
    defer counters.deinit(allocator);
    try interaction.registerRangeCheckCounters(&counters, &views);
    try std.testing.expect(
        counters.get(.range_check_20).signedTotal().eql(M31.one().neg()),
    );
    try std.testing.expect(
        counters.get(.range_check_8_8).signedTotal().eql(M31.one().neg()),
    );

    // The largest admitted predecessor has high limb 63 and is accepted.
    const placement = try infra.BitReversalTable.init(allocator, 4);
    defer placement.deinit(allocator);
    const active_row = placement.map(0);
    main.columns[3][active_row] = M31.fromCanonical(state_chain.CLOCK_PREV_BOUND - 1);
    main.columns[8][active_row] =
        M31.fromCanonical((@as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS) - 1);
    main.columns[9][active_row] =
        M31.fromCanonical((@as(u32, 1) << state_chain.CLOCK_PREV_HIGH_BITS) - 1);
    var max_counters = try counter.Set.init(allocator);
    defer max_counters.deinit(allocator);
    try interaction.registerRangeCheckCounters(&max_counters, &views);

    // A forged high limb is rejected by the same exact-buffer ingestion path.
    main.columns[9][active_row] =
        M31.fromCanonical(@as(u32, 1) << state_chain.CLOCK_PREV_HIGH_BITS);
    var forged_counters = try counter.Set.init(allocator);
    defer forged_counters.deinit(allocator);
    try std.testing.expectError(
        error.ValueOutOfRange,
        interaction.registerRangeCheckCounters(&forged_counters, &views),
    );
}

test "long register gaps compose clock rows into opcode access witnesses" {
    const allocator = std.testing.allocator;
    var tracker = state_chain.StateChainTracker.init(allocator);
    defer tracker.deinit();

    const source_reg: u5 = 2;
    const destination_reg: u5 = 1;
    const source_raw_clock: u32 = 3;
    const destination_raw_clock: u32 = 5;
    const instruction_clock: u32 = state_chain.MAX_CLOCK_DIFF / 2 + 4;
    const source_value: u32 = 0x1122_3344;
    const destination_previous: u32 = 0x5566_7788;
    const destination_next: u32 = 0x99aa_bbcc;
    tracker.reg_last_clk[source_reg] = source_raw_clock;
    tracker.reg_last_clk[destination_reg] = destination_raw_clock;

    const inst = try DecodedInst.decode(0x0011_0093); // ADDI x1, x2, 1
    const witness = access_witness.capture(&tracker, inst, instruction_clock);
    const expected_source_previous = source_raw_clock + 2 * state_chain.MAX_CLOCK_DIFF;
    const expected_destination_previous = destination_raw_clock + 2 * state_chain.MAX_CLOCK_DIFF;
    try std.testing.expectEqual(expected_source_previous, witness.rs1_prev_clock);
    try std.testing.expectEqual(expected_destination_previous, witness.rd_prev_clock);

    try witness.recordRegisters(
        &tracker,
        inst,
        source_value,
        0,
        destination_previous,
        destination_next,
    );
    try std.testing.expectEqual(@as(usize, 4), tracker.clock_updates_reg.items.len);
    try std.testing.expectEqual(@as(usize, 2), tracker.accesses.items.len);

    const source_limbs = state_chain.StateChainTracker.decomposeU32(source_value);
    const destination_previous_limbs = state_chain.StateChainTracker.decomposeU32(
        destination_previous,
    );
    const destination_next_limbs = state_chain.StateChainTracker.decomposeU32(destination_next);
    const expected_regs = [_]u5{ source_reg, destination_reg };
    const expected_raw_clocks = [_]u32{ source_raw_clock, destination_raw_clock };
    const expected_previous_clocks = [_]u32{
        expected_source_previous,
        expected_destination_previous,
    };
    const expected_access_clocks = [_]u32{ witness.rs1_clock, witness.rd_clock };
    const previous_values = [_][4]M31{ source_limbs, destination_previous_limbs };

    for (0..2) |chain_index| {
        var previous_positive: ?@import("lookups/entry.zig").Entry = null;
        for (0..2) |update_index| {
            const update = tracker.clock_updates_reg.items[chain_index * 2 + update_index];
            const expected_prev = expected_raw_clocks[chain_index] +
                @as(u32, @intCast(update_index)) * state_chain.MAX_CLOCK_DIFF;
            const expected_next = expected_prev + state_chain.MAX_CLOCK_DIFF;
            try std.testing.expectEqual(@as(u1, 0), update.addr_space);
            try std.testing.expectEqual(@as(u32, expected_regs[chain_index]), update.addr);
            try std.testing.expectEqual(expected_prev, update.clk_prev);
            try std.testing.expectEqual(expected_next, update.clk);
            try std.testing.expectEqual(previous_values[chain_index], update.valueLimbs());

            const entries = interaction.orderedEntries(rowForClockUpdate(update));
            try std.testing.expect(entries.entries[0].numerator.eql(QM31.one().neg()));
            try std.testing.expect(entries.entries[1].numerator.eql(QM31.one()));
            try expectMemoryTuple(
                entries.entries[0],
                0,
                expected_regs[chain_index],
                expected_prev,
                previous_values[chain_index],
            );
            try expectMemoryTuple(
                entries.entries[1],
                0,
                expected_regs[chain_index],
                expected_next,
                previous_values[chain_index],
            );
            if (previous_positive) |prior| try expectSameMemoryTuple(prior, entries.entries[0]);
            previous_positive = entries.entries[1];
        }

        const access = tracker.accesses.items[chain_index];
        try std.testing.expectEqual(@as(u1, 0), access.addr_space);
        try std.testing.expectEqual(@as(u32, expected_regs[chain_index]), access.addr);
        try std.testing.expectEqual(expected_access_clocks[chain_index], access.clk);
        try std.testing.expectEqual(expected_previous_clocks[chain_index], access.clk_prev);
        try std.testing.expect(
            expected_access_clocks[chain_index] - access.clk_prev <=
                state_chain.MAX_CLOCK_DIFF,
        );
        const final_update_entries = interaction.orderedEntries(rowForClockUpdate(
            tracker.clock_updates_reg.items[chain_index * 2 + 1],
        ));
        try expectMemoryTuple(
            final_update_entries.entries[1],
            0,
            expected_regs[chain_index],
            access.clk_prev,
            previous_values[chain_index],
        );
    }

    try std.testing.expectEqual(source_limbs, tracker.accesses.items[0].valueLimbs());
    try std.testing.expectEqual(destination_next_limbs, tracker.accesses.items[1].valueLimbs());
}

test "clock update component owns exact bounds and aliases both selectors" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const component = ClockUpdateComponent.initVerifier(
        4,
        7,
        11,
        13,
        17,
        &relations,
        .{QM31.zero()} ** interaction.N_SUMS,
    );
    try std.testing.expectEqual(@as(usize, interaction.N_SUMS + 3), component.nConstraints());
    _ = component.asVerifierComponent();
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 2), bounds.items[0].len);
    try std.testing.expectEqual(interaction.N_MAIN_COLUMNS, bounds.items[1].len);
    try std.testing.expectEqual(interaction.N_INTERACTION_COLUMNS, bounds.items[2].len);
    for (bounds.items) |tree| for (tree) |log_size| try std.testing.expectEqual(@as(u32, 4), log_size);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 7, 11 }, indices);
}

test "clock update generated interaction satisfies row semantics and rejects mutation" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var main = try testMain(allocator, 4);
    defer main.deinit(allocator);
    var generated = try interaction.generate(allocator, &main.columns, 4, &relations);
    defer generated.deinit(allocator);
    const component = try ClockUpdateComponent.initProver(
        4,
        0,
        1,
        0,
        0,
        &relations,
        generated.claims,
    );
    _ = component.asProverComponent();
    const placement = try infra.BitReversalTable.init(allocator, 4);
    defer placement.deinit(allocator);
    const committed_row = placement.map(0);
    const previous_row = placement.map((@as(usize, 1) << 4) - 1);
    var sampled: [interaction.N_MAIN_COLUMNS]QM31 = undefined;
    for (&sampled, &main.columns) |*value, column| value.* = QM31.fromBase(column[committed_row]);
    var current: [interaction.N_SUMS]QM31 = undefined;
    var previous: [interaction.N_SUMS]QM31 = undefined;
    for (0..interaction.N_SUMS) |index| {
        current[index] = secureAt(generated.columns[index * 4 ..][0..4], committed_row);
        previous[index] = secureAt(generated.columns[index * 4 ..][0..4], previous_row);
    }
    try std.testing.expect((try component.evaluateRow(
        &sampled,
        current,
        previous,
        QM31.one(),
        QM31.one(),
    )).allZero());
    sampled[8] = q(8);
    const bad_recomposition = try component.evaluateRow(
        &sampled,
        current,
        previous,
        QM31.one(),
        QM31.one(),
    );
    try std.testing.expect(!bad_recomposition.values[interaction.N_SUMS + 2].isZero());
    sampled[8] = q(7);
    sampled[0] = q(2);
    try std.testing.expect(!(try component.evaluateRow(
        &sampled,
        current,
        previous,
        QM31.one(),
        QM31.one(),
    )).allZero());
}

test "clock update OODS uses exact global offsets" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var committed = try testMain(allocator, 4);
    defer committed.deinit(allocator);
    var generated = try interaction.generate(allocator, &committed.columns, 4, &relations);
    defer generated.deinit(allocator);
    const first_index: usize = 2;
    const active_index: usize = 3;
    const main_offset: usize = 5;
    const secure_offset: usize = 7;
    const component = ClockUpdateComponent.initVerifier(
        4,
        first_index,
        active_index,
        main_offset,
        secure_offset,
        &relations,
        generated.claims,
    );
    const placement = try infra.BitReversalTable.init(allocator, 4);
    defer placement.deinit(allocator);
    const committed_row = placement.map(0);
    const previous_row = placement.map((@as(usize, 1) << 4) - 1);

    var pp_storage = [_][1]QM31{.{q(19)}} ** 5;
    pp_storage[first_index][0] = QM31.one();
    pp_storage[active_index][0] = QM31.one();
    var pp: [pp_storage.len][]QM31 = undefined;
    for (&pp, &pp_storage) |*column, *values| column.* = values;
    var main_storage = [_][1]QM31{.{q(23)}} ** (main_offset + interaction.N_MAIN_COLUMNS + 2);
    for (main_storage[main_offset..][0..interaction.N_MAIN_COLUMNS], &committed.columns) |*value, column| {
        value[0] = QM31.fromBase(column[committed_row]);
    }
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var secure_storage = [_][2]QM31{.{ q(29), q(31) }} **
        (secure_offset + interaction.N_INTERACTION_COLUMNS + 2);
    for (0..interaction.N_SUMS) |sum_index| {
        const current = generated.claims[sum_index].toM31Array();
        const previous = secureAt(
            generated.columns[sum_index * 4 ..][0..4],
            previous_row,
        ).toM31Array();
        for (0..4) |coordinate| {
            const index = sum_index * 4 + coordinate;
            secure_storage[secure_offset + index][0] = QM31.fromBase(current[coordinate]);
            secure_storage[secure_offset + index][1] = QM31.fromBase(previous[coordinate]);
        }
    }
    var secure: [secure_storage.len][]QM31 = undefined;
    for (&secure, &secure_storage) |*column, *values| column.* = values;
    var trees = [_][][]QM31{ &pp, &main, &secure };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());
    pp_storage[active_index][0] = QM31.zero();
    var mutated = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &mutated,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!mutated.finalize().isZero());
}

test "clock update on-domain path enforces inactive padding" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const log_size: u32 = 4;
    const eval_log_size: u32 = 5;
    const eval_size: usize = 1 << eval_log_size;
    const values = try allocator.alloc(M31, eval_size);
    defer allocator.free(values);
    @memset(values, M31.zero());
    const zero_poly = prover_component.Poly{ .log_size = eval_log_size, .values = values };
    var pp = [_]prover_component.Poly{zero_poly} ** 2;
    var main = [_]prover_component.Poly{zero_poly} ** interaction.N_MAIN_COLUMNS;
    var secure = [_]prover_component.Poly{zero_poly} ** interaction.N_INTERACTION_COLUMNS;
    var trees = [_][]const prover_component.Poly{ &pp, &main, &secure };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    const component = try ClockUpdateComponent.initProver(
        log_size,
        0,
        1,
        0,
        0,
        &relations,
        .{QM31.zero()} ** interaction.N_SUMS,
    );
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    for (0..result.len()) |row| try std.testing.expect(result.at(row).isZero());

    const active_values = try allocator.alloc(M31, eval_size);
    defer allocator.free(active_values);
    @memset(active_values, M31.one());
    pp[1] = .{ .log_size = eval_log_size, .values = active_values };
    var mutated = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer mutated.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace_data, &mutated);
    var mutated_result = try mutated.finalize();
    defer mutated_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row| {
        saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    }
    try std.testing.expect(saw_nonzero);

    // The coordinator-prepared capability owns every allocation. Poison the
    // allocator after preparation so the same production row loop proves it
    // performs no hidden worker-side allocation.
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer prepared_accumulator.deinit();
    const prover = component.asProverComponent();
    try std.testing.expect(prover.prepare_domain_evaluator != null);
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(
        eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expect(prepared.resources.shared_resident_bytes > 0);
    try std.testing.expectEqual(
        prover_engine.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );

    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;
    try runPreparedOnBoundedHelper(&prepared);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    var prepared_result = try prepared_accumulator.finalize();
    defer prepared_result.deinit(prepared_allocator);
    try std.testing.expectEqual(mutated_result.len(), prepared_result.len());
    for (0..prepared_result.len()) |row| {
        try std.testing.expect(mutated_result.at(row).eql(prepared_result.at(row)));
    }

    // A pre-existing sibling failure is observed at the first bounded poll.
    // Cancellation returns successfully so it cannot replace that failure as
    // the task graph's canonical cause.
    var cancelled_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = (try prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &trace_data,
        &cancelled_accumulator,
    )).?;
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    var cancelled_context = testLeafTaskContext(cancelled.context, &cancelled_token);
    try cancelled.run(&cancelled_context);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(allocator);
    for (0..cancelled_result.len()) |row| {
        try std.testing.expect(cancelled_result.at(row).isZero());
    }

    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareClockUpdateDomain,
        .{ &component, &trace_data, eval_log_size },
    );
}

fn generateInteraction(
    allocator: std.mem.Allocator,
    columns: []const []const M31,
    relations: *const relations_mod.Relations,
) !void {
    var generated = try interaction.generate(allocator, columns, 4, relations);
    defer generated.deinit(allocator);
}

test "clock update interaction rejects malformed columns and rolls back allocations" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var main = try testMain(allocator, 4);
    defer main.deinit(allocator);
    var views: [interaction.N_MAIN_COLUMNS][]const M31 = undefined;
    for (&views, &main.columns) |*view, column| view.* = column;
    try std.testing.expectError(
        error.InvalidColumnCount,
        interaction.generate(allocator, views[0 .. views.len - 1], 4, &relations),
    );
    const saved = views[0];
    views[0] = saved[0 .. saved.len - 1];
    try std.testing.expectError(
        error.InvalidColumnLength,
        interaction.generate(allocator, &views, 4, &relations),
    );
    views[0] = saved;
    try std.testing.checkAllAllocationFailures(
        allocator,
        generateInteraction,
        .{ &views, &relations },
    );
}

fn allocateMetadata(allocator: std.mem.Allocator, component: *const ClockUpdateComponent) !void {
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound() + 2,
    );
    defer masks.deinitDeep(allocator);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
}

test "clock update metadata allocations roll back completely" {
    const relations = relations_mod.Relations.dummy();
    const component = ClockUpdateComponent.initVerifier(
        4,
        0,
        1,
        0,
        0,
        &relations,
        .{QM31.zero()} ** interaction.N_SUMS,
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateMetadata,
        .{&component},
    );
}
