//! Exact committed-column differential for the R-002 production kernel.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const memory_trace = @import("../air/memory_commitment/trace.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_table = @import("../air/program/table.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const public_data = @import("../air/public_data.zig");
const infra = @import("../infra_trace.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const interaction_production = @import("interaction_trace_plan_execution_production.zig");
const interaction_witness_work = @import("interaction_witness_work.zig");
const lookup_sources = @import("lookup_sources.zig");
const main_trace = @import("main_trace.zig");
const main_witness_work = @import("main_witness_work.zig");
const opcode_trace = @import("opcode_trace.zig");
const plan_mod = @import("main_trace_plan.zig");
const poseidon_witness_work = @import("poseidon_witness_work.zig");
const production = @import("main_trace_plan_execution_production.zig");
const statement_validation = @import("statement_validation.zig");
const tree2_main_source = @import("tree2_main_source.zig");

const ROWS: usize = 2 * plan_mod.OPCODE_ROWS_PER_CHUNK;
const TEST_STACK_BYTES: usize = work_pool.WORKER_STACK_SIZE;

test "main trace: incomplete witness field authority cannot publish exact work" {
    const allocator = std.testing.allocator;
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "Debug",
        "riscv-main-trace",
        .{ .capture_work = true },
    );
    defer recorder.deinit();

    try main_trace.planIncompleteMainWitnessFieldWork(&recorder);
    const work = recorder.workCaptureRecorder() orelse unreachable;
    try std.testing.expect(work.incomplete);
    const site_index = @intFromEnum(
        prover_api.work_profile.Site.main_witness_field,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[site_index]);
    try std.testing.expectEqual(@as(u64, 0), work.completed_sites[site_index]);
    const snapshot = try recorder.workSnapshot();
    try snapshot.validate();
    try std.testing.expect(!snapshot.completeExact());
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    execution: trace_mod.Trace,
    chain: state_chain.StateChainTracker,
    witness: commitment_witness.CommitmentWitness,
    statement: statement_mod.RiscVStatement,
    geometry: @import("statement_geometry.zig").Geometry,

    fn init(allocator: std.mem.Allocator) !*Fixture {
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.execution = trace_mod.Trace.init(allocator);
        errdefer self.execution.deinit();
        try self.execution.rows.ensureTotalCapacity(allocator, ROWS);
        for (0..ROWS) |index| self.execution.rows.appendAssumeCapacity(testRow(index));
        self.execution.initial_pc = 0x1000;
        self.execution.final_pc = 0x1004;
        self.execution.step_count = ROWS;

        self.chain = state_chain.StateChainTracker.init(allocator);
        errdefer self.chain.deinit();
        try self.chain.recordRegAccess(
            7,
            state_chain.MAX_CLOCK_DIFF + 5,
            0x4433_2211,
        );

        var program = try program_commitment.build(
            allocator,
            &.{program_table.Fetch{ .pc = 0x1000, .word = 0x0010_0093 }},
            &.{},
        );
        errdefer program.deinit(allocator);
        program.rows[0].multiplicity = ROWS;
        var boundary = try memory_boundary.build(allocator, &.{.{
            .addr = 0x2000,
            .initial_word = 0x1122_3344,
            .final_word = 0x5566_7788,
            .final_clock = 9,
        }});
        errdefer boundary.deinit(allocator);
        var merkle_rows: std.ArrayList(merkle_node.NodeRow) = .empty;
        errdefer merkle_rows.deinit(allocator);
        var poseidon_calls: std.ArrayList(poseidon2_air.Call) = .empty;
        errdefer poseidon_calls.deinit(allocator);
        try appendTreeCalls(allocator, &poseidon_calls, program.tree);
        if (boundary.initial_tree) |tree| {
            try appendTreeCalls(allocator, &poseidon_calls, tree);
        }
        if (boundary.final_tree) |tree| {
            try appendTreeCalls(allocator, &poseidon_calls, tree);
        }
        if (boundary.initial_tree) |tree| {
            try appendTreeRows(allocator, &merkle_rows, tree);
        }
        if (boundary.final_tree) |tree| {
            try appendTreeRows(allocator, &merkle_rows, tree);
        }
        try appendTreeRows(allocator, &merkle_rows, program.tree);
        self.witness = .{
            .boundary = boundary,
            .program = program,
            .poseidon_calls = poseidon_calls,
            .merkle_rows = merkle_rows,
        };
        self.statement = try testStatement(&self.witness, &self.chain);
        const merkle_index: usize = 2;
        self.geometry = .{
            .program_log_size = self.statement.infra_descs[0].log_size,
            .merkle_log_size = self.statement.infra_descs[merkle_index].log_size,
            .poseidon_log_size = self.statement.infra_descs[merkle_index + 1].log_size,
            .clock_update_log = self.statement.infra_descs[merkle_index + 2].log_size,
            .merkle_infra_index = merkle_index,
            .poseidon_infra_index = merkle_index + 1,
            .clock_infra_index = merkle_index + 2,
        };
        return self;
    }

    fn deinit(self: *Fixture) void {
        const allocator = self.allocator;
        self.witness.deinit(allocator);
        self.chain.deinit();
        self.execution.deinit();
        allocator.destroy(self);
    }
};

const Reference = struct {
    allocator: std.mem.Allocator,
    opcode: opcode_trace.Columns,
    program: program_commitment.Columns,
    memory: memory_trace.Columns,
    merkle: merkle_node.Columns,
    poseidon: poseidon2_air.Columns,
    clock: [infra.CLOCK_UPDATE_COLS][]M31,
    lookup: [lookup_schema.KIND_COUNT][]M31,

    fn init(allocator: std.mem.Allocator, fixture: *const Fixture) !*Reference {
        const self = try allocator.create(Reference);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.opcode = try opcode_trace.generate(
            allocator,
            &fixture.execution,
            fixture.statement,
        );
        errdefer self.opcode.deinit(allocator, fixture.statement);
        self.program = try program_commitment.generateMain(
            allocator,
            fixture.witness.program.rows,
            fixture.geometry.program_log_size,
        );
        errdefer self.program.deinit(allocator);
        const boundary = fixture.witness.boundary.?;
        self.memory = try memory_trace.generate(
            allocator,
            boundary.rows,
            fixture.statement.infra_descs[1].log_size,
        );
        errdefer self.memory.deinit(allocator);
        self.merkle = try merkle_node.generateMain(
            allocator,
            fixture.witness.merkleRows(),
            fixture.geometry.merkle_log_size,
        );
        errdefer self.merkle.deinit(allocator);
        self.poseidon = try poseidon2_air.generateMain(
            allocator,
            fixture.witness.poseidonCalls(),
            fixture.geometry.poseidon_log_size,
        );
        errdefer self.poseidon.deinit(allocator);
        const generated_clock = try infra.genClockUpdateColumns(
            allocator,
            &fixture.chain,
            fixture.geometry.clock_update_log,
        );
        self.clock = generated_clock.columns;
        errdefer infra.freeClockUpdateColumns(allocator, &self.clock);

        var lookup = try lookup_sources.ingest(
            allocator,
            fixture.statement,
            &self.opcode,
            .{ .unrepresentable = .reject },
        );
        defer lookup.deinit(allocator);
        try lookup_sources.registerProgram(
            &lookup.counters,
            fixture.witness.program.rows,
        );
        try lookup_sources.registerMemoryBoundary(
            &lookup.counters,
            boundary.rows,
        );
        var clock_views: [infra.CLOCK_UPDATE_COLS][]const M31 = undefined;
        for (&clock_views, self.clock) |*view, column| view.* = column;
        try clock_update_interaction.registerRangeCheckCounters(
            &lookup.counters,
            &clock_views,
        );
        var initialized: usize = 0;
        errdefer for (self.lookup[0..initialized]) |column| allocator.free(column);
        for (component_order.lookupTables(), 0..) |kind, index| {
            self.lookup[index] = try lookup.counters.get(kind).committedColumn(
                allocator,
            );
            initialized += 1;
        }
        return self;
    }

    fn deinit(self: *Reference, statement: statement_mod.RiscVStatement) void {
        const allocator = self.allocator;
        for (self.lookup) |column| allocator.free(column);
        infra.freeClockUpdateColumns(allocator, &self.clock);
        self.poseidon.deinit(allocator);
        self.merkle.deinit(allocator);
        self.program.deinit(allocator);
        self.memory.deinit(allocator);
        self.opcode.deinit(allocator, statement);
        allocator.destroy(self);
    }
};

test "production Tree-1: legacy and serial N=1/2/4 columns are byte-identical" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const reference = try Reference.init(allocator, fixture);
    defer reference.deinit(fixture.statement);

    const poseidon_authority = poseidon_witness_work.Authority.init();
    var initial_poseidon_work = poseidon_witness_work.Shard{};
    try initial_poseidon_work.observe(
        &poseidon_authority,
        try poseidon_witness_work.complete(
            &poseidon_authority,
            .sparse_tree_permutation,
            @intCast(fixture.witness.merkleRows().len),
        ),
    );
    fixture.witness.poseidon_work = initial_poseidon_work;

    const legacy_work_receipt = try main_witness_work.issueLegacyReceipt(
        &fixture.statement,
        fixture.execution.rows.items,
        .{
            .counter_set_merges = reference.opcode.counter_set_merges,
            .direct_semantic_audit_performed = reference.opcode.direct_semantic_audit_performed,
        },
    );
    const legacy_work_authority = try main_witness_work.Authority.init();
    try legacy_work_receipt.validate(&legacy_work_authority);
    try std.testing.expectEqual(
        @as(u64, ROWS),
        legacy_work_receipt.completed.opcode_rows[
            @intFromEnum(trace_mod.OpcodeFamily.base_alu_imm)
        ],
    );
    try std.testing.expectEqual(
        @as(u64, @intCast(reference.opcode.counter_set_merges)),
        legacy_work_receipt.completed.counter_set_merges,
    );

    var digests: [3][32]u8 = undefined;
    var work_digests: [3][32]u8 = undefined;
    var work_operations: [3]prover_api.work_profile.FieldOperations = undefined;
    var counter_set_merges: [3]u64 = undefined;
    var poseidon_digests: [3][32]u8 = undefined;
    var poseidon_operations: [3]prover_api.work_profile.FieldOperations = undefined;
    var relation_channel = Blake2sChannel{};
    const relations = try relation_challenges.Relations.draw(
        allocator,
        &relation_channel,
    );
    const interaction_pow: u64 = 7;
    const interaction_authority = interaction_witness_work.Authority.init();
    const interaction_session = interaction_witness_work.baseSessionDigest(
        interaction_pow,
        &relations,
    );
    const challenge_receipt = try interaction_witness_work.completeBaseChallenges(
        &interaction_authority,
        .base,
        interaction_session,
    );
    var interaction_digests: [3][32]u8 = undefined;
    var interaction_operations: [3]prover_api.work_profile.FieldOperations = undefined;
    for ([_]usize{ 1, 2, 4 }, 0..) |workers, index| {
        const plan = try plan_mod.build(
            &fixture.statement,
            testOptions(workers),
        );
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var prepared = try production.Prepared.prepare(
            failing.allocator(),
            &plan,
            &fixture.statement,
            .{
                .execution_trace = &fixture.execution,
                .witness = &fixture.witness,
                .geometry = fixture.geometry,
                .state_chain = &fixture.chain,
                .capture_main_witness_work = true,
            },
        );
        defer prepared.deinit();
        try std.testing.expectError(
            error.Tree1ProductionOutputNotPublished,
            prepared.mainColumns(),
        );

        var pool: work_pool.WorkPool = undefined;
        var pool_initialized = false;
        defer if (pool_initialized) pool.deinit();
        if (workers > 1) {
            try pool.initInPlaceWithOptions(.{
                .worker_count = workers,
                .stack_size = TEST_STACK_BYTES,
                .backing_allocator = allocator,
            });
            pool_initialized = true;
        }
        const allocation_count = failing.alloc_index;
        const resize_count = failing.resize_index;
        failing.fail_index = allocation_count;
        failing.resize_fail_index = resize_count;
        const report = try prepared.execute(
            if (pool_initialized) &pool else null,
        );
        try std.testing.expectEqual(allocation_count, failing.alloc_index);
        try std.testing.expectEqual(resize_count, failing.resize_index);
        try std.testing.expect(!failing.has_induced_failure);
        const work_receipt = try prepared.mainWitnessWorkReceipt();
        const poseidon_receipt = try prepared.poseidonWitnessWorkReceipt();
        try poseidon_receipt.validate(&poseidon_authority);
        work_digests[index] = work_receipt.source_digest;
        work_operations[index] = work_receipt.completed.operations;
        counter_set_merges[index] = work_receipt.completed.counter_set_merges;
        poseidon_digests[index] = poseidon_receipt.source_digest;
        poseidon_operations[index] = poseidon_receipt.completed.operations;
        try std.testing.expectEqual(
            @as(u64, ROWS),
            work_receipt.completed.opcode_rows[
                @intFromEnum(
                    trace_mod.OpcodeFamily.base_alu_imm,
                )
            ],
        );
        try std.testing.expectEqual(
            @as(u64, @intCast(fixture.witness.program.rows.len)),
            work_receipt.completed.program_rows,
        );
        try std.testing.expectEqual(
            @as(u64, @intCast(fixture.witness.program.rows.len)),
            work_receipt.completed.program_seed_rows,
        );
        try std.testing.expectEqual(
            initial_poseidon_work.counts.sparse_tree_permutations,
            poseidon_receipt.completed.counts.sparse_tree_permutations,
        );
        try std.testing.expectEqual(
            @as(u64, @intCast(fixture.witness.poseidonCalls().len)),
            poseidon_receipt.completed.counts.base_air_rows,
        );
        try std.testing.expectEqual(
            @as(usize, plan.task_counts.prepare_wave) +
                plan.task_counts.generation_wave +
                plan.task_counts.reduce_wave +
                plan.task_counts.audit_wave +
                plan.task_counts.lookup_seed_wave +
                plan.task_counts.finalization_wave +
                plan.task_counts.seal_wave,
            report.succeeded_tasks,
        );
        try expectReference(reference, fixture, &prepared);

        const interaction_claim = try allocator.create(
            statement_mod.RiscVInteractionClaim,
        );
        defer allocator.destroy(interaction_claim);
        interaction_claim.initZeroInto();
        interaction_claim.n_components = fixture.statement.n_components;
        interaction_claim.n_infra = fixture.statement.n_infra;
        interaction_claim.interaction_pow = interaction_pow;
        const main_source = tree2_main_source.Source.fromPlanned(&prepared);
        var prepared_interaction = try interaction_production.Prepared.prepareWithWorkReceipt(
            allocator,
            &fixture.statement,
            .{
                .witness = &fixture.witness,
                .geometry = fixture.geometry,
                .main_source = main_source,
                .relations = &relations,
                .claim = interaction_claim,
            },
            testOptions(workers).execution,
            workers,
            TEST_STACK_BYTES,
            .{
                .authority = interaction_authority,
                .session_digest = interaction_session,
                .challenge_receipt = challenge_receipt,
            },
        );
        defer prepared_interaction.deinit();
        _ = try prepared_interaction.execute(
            if (pool_initialized) &pool else null,
        );
        const interaction_receipt = try prepared_interaction.interactionWorkReceipt();
        try interaction_receipt.validate(&interaction_authority);
        try std.testing.expect(interaction_receipt.completed.operations.additions > 0);
        try std.testing.expect(interaction_receipt.completed.operations.multiplications > 0);
        try std.testing.expect(interaction_receipt.completed.operations.inversions > 0);
        interaction_digests[index] = interaction_receipt.receipt_digest;
        interaction_operations[index] = interaction_receipt.completed.operations;

        digests[index] = try digestColumns(try prepared.mainColumns());
        var commitment = try prepared.takeMainCommitment();
        defer commitment.deinit(failing.allocator());
        try std.testing.expectEqual(
            @as(usize, 1),
            commitment.backingBuffers().?.len,
        );
        try expectGroupedArena(&commitment);
        try std.testing.expectError(
            error.Tree1ProductionOutputAlreadyTransferred,
            prepared.mainColumns(),
        );
        // Tree 2's retained authority survives the Tree-1 ownership move.
        try std.testing.expectEqualSlices(
            M31,
            reference.opcode.components[0].columns[0],
            try prepared.retainedOpcodeColumn(0, 0),
        );
    }
    try std.testing.expectEqual(digests[0], digests[1]);
    try std.testing.expectEqual(digests[0], digests[2]);
    try std.testing.expectEqual(work_digests[0], work_digests[1]);
    try std.testing.expectEqual(work_digests[0], work_digests[2]);
    try std.testing.expectEqual(poseidon_digests[0], poseidon_digests[1]);
    try std.testing.expectEqual(poseidon_digests[0], poseidon_digests[2]);
    try std.testing.expectEqual(poseidon_operations[0], poseidon_operations[1]);
    try std.testing.expectEqual(poseidon_operations[0], poseidon_operations[2]);
    try std.testing.expectEqual(interaction_digests[0], interaction_digests[1]);
    try std.testing.expectEqual(interaction_digests[0], interaction_digests[2]);
    try std.testing.expectEqual(interaction_operations[0], interaction_operations[1]);
    try std.testing.expectEqual(interaction_operations[0], interaction_operations[2]);
    const work_authority = try main_witness_work.Authority.init();
    var normalized: [3]prover_api.work_profile.FieldOperations = undefined;
    for (&normalized, work_operations, counter_set_merges) |
        *value,
        operations,
        merges,
    | {
        value.* = operations;
        value.additions -= work_authority.fixed_table_cells * merges;
    }
    try std.testing.expectEqual(normalized[0], normalized[1]);
    try std.testing.expectEqual(normalized[0], normalized[2]);
    try expectCancellationIsTransactional(allocator, fixture);
}

fn expectCancellationIsTransactional(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
) !void {
    const plan = try plan_mod.build(&fixture.statement, testOptions(1));
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var prepared = try production.Prepared.prepare(
        failing.allocator(),
        &plan,
        &fixture.statement,
        .{
            .execution_trace = &fixture.execution,
            .witness = &fixture.witness,
            .geometry = fixture.geometry,
            .state_chain = &fixture.chain,
            .capture_main_witness_work = true,
        },
    );
    defer prepared.deinit();

    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;
    try std.testing.expect(prepared.requestCancellation());
    try std.testing.expectError(error.Tree1EpochCancelled, prepared.execute(null));
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        prepared.epoch.plannedTaskCount(),
        prepared.epoch.report().?.unsubmitted_cancelled_tasks,
    );
    try std.testing.expectError(
        error.Tree1ProductionOutputNotPublished,
        prepared.mainColumns(),
    );
    try std.testing.expectError(
        error.Tree1ProductionOutputNotPublished,
        prepared.takeMainCommitment(),
    );
    try std.testing.expectError(
        error.Tree1ProductionOutputNotPublished,
        prepared.retainedOpcodeColumn(0, 0),
    );
    try std.testing.expectError(
        error.Tree1ProductionOutputNotPublished,
        prepared.mainWitnessWorkReceipt(),
    );
    try std.testing.expectError(
        error.Tree1ProductionOutputNotPublished,
        prepared.poseidonWitnessWorkReceipt(),
    );
}

fn testStatement(
    witness: *const commitment_witness.CommitmentWitness,
    chain: *const state_chain.StateChainTracker,
) !statement_mod.RiscVStatement {
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = 2;
    statement.initial_pc = 0x1000;
    statement.final_pc = 0x1004;
    statement.total_steps = ROWS;
    statement.public_data = std.mem.zeroes(public_data.PublicData);
    for (0..statement.n_components) |index| {
        statement.component_descs[index] = .{
            .family = .base_alu_imm,
            .log_size = 16,
            .n_rows = plan_mod.OPCODE_ROWS_PER_CHUNK,
            .n_columns = trace_mod.nColumnsForFamily(.base_alu_imm),
        };
    }
    var infra_index: usize = 0;
    statement.infra_descs[infra_index] = .{
        .kind = .program,
        .log_size = statement_validation.computeLogSize(witness.program.rows.len),
        .n_rows = @intCast(witness.program.rows.len),
        .n_columns = program_commitment.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    const boundary = witness.boundary.?;
    statement.infra_descs[infra_index] = .{
        .kind = .memory,
        .log_size = @max(
            @as(u32, 4),
            statement_validation.computeLogSize(boundary.rows.len),
        ),
        .n_rows = @intCast(boundary.rows.len),
        .n_columns = memory_trace.N_COLUMNS,
    };
    infra_index += 1;
    const merkle_log = @max(
        @as(u32, 4),
        statement_validation.computeLogSize(witness.merkleRows().len),
    );
    statement.infra_descs[infra_index] = .{
        .kind = .merkle,
        .log_size = merkle_log,
        .n_rows = @intCast(witness.merkleRows().len),
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    statement.infra_descs[infra_index] = .{
        .kind = .poseidon2,
        .log_size = merkle_log,
        .n_rows = @intCast(witness.poseidonCalls().len),
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    infra_index += 1;
    const clock_rows = chain.clock_updates_reg.items.len +
        chain.clock_updates_mem.items.len;
    statement.infra_descs[infra_index] = .{
        .kind = .clock_update,
        .log_size = @max(
            @as(u32, 4),
            statement_validation.computeLogSize(clock_rows),
        ),
        .n_rows = @intCast(clock_rows),
        .n_columns = infra.CLOCK_UPDATE_COLS,
    };
    infra_index += 1;
    for (component_order.lookupTables()) |kind| {
        statement.infra_descs[infra_index] = .{
            .kind = statement_mod.infraKindForTable(kind),
            .log_size = lookup_schema.logSize(kind),
            .n_rows = @intCast(lookup_schema.size(kind)),
            .n_columns = 1,
        };
        infra_index += 1;
    }
    statement.n_infra = @intCast(infra_index);
    return statement;
}

fn testOptions(workers: usize) plan_mod.BuildOptions {
    return .{
        .execution = .{
            .worker_count = workers,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        },
        .pool_capacity = workers,
        .worker_stack_bytes = TEST_STACK_BYTES,
        .enable_opcode_audit = true,
    };
}

fn testRow(_: usize) trace_mod.TraceRow {
    return .{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x0010_0093,
    };
}

fn expectReference(
    reference: *const Reference,
    fixture: *const Fixture,
    prepared: *const production.Prepared,
) !void {
    const actual = try prepared.mainColumns();
    var offset: usize = 0;
    for (0..fixture.statement.n_components) |component_index| {
        const component = reference.opcode.components[component_index];
        for (component.columns[0..component.n_columns], 0..) |expected, column| {
            try expectColumn(actual[offset], expected);
            try std.testing.expectEqualSlices(
                M31,
                expected,
                try prepared.retainedOpcodeColumn(component_index, column),
            );
            offset += 1;
        }
    }
    for (reference.program.values) |expected| {
        try expectColumn(actual[offset], expected);
        offset += 1;
    }
    for (reference.memory.values) |expected| {
        try expectColumn(actual[offset], expected);
        offset += 1;
    }
    for (reference.merkle.values) |expected| {
        try expectColumn(actual[offset], expected);
        offset += 1;
    }
    for (reference.poseidon.values) |expected| {
        try expectColumn(actual[offset], expected);
        offset += 1;
    }
    for (reference.clock, 0..) |expected, column| {
        try expectColumn(actual[offset], expected);
        try std.testing.expectEqualSlices(
            M31,
            expected,
            try prepared.retainedClockColumn(column),
        );
        offset += 1;
    }
    for (reference.lookup) |expected| {
        try expectColumn(actual[offset], expected);
        offset += 1;
    }
    try std.testing.expectEqual(actual.len, offset);
}

fn expectColumn(
    actual: @import("stwo_prover_engine").pcs.ColumnEvaluation,
    expected: []const M31,
) !void {
    try std.testing.expectEqual(expected.len, actual.values.len);
    try std.testing.expectEqualSlices(M31, expected, actual.values);
}

fn digestColumns(
    columns: []const @import("stwo_prover_engine").pcs.ColumnEvaluation,
) ![32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| {
        var log_size_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &log_size_bytes, column.log_size, .little);
        hasher.update(&log_size_bytes);
        hasher.update(std.mem.sliceAsBytes(column.values));
    }
    return hasher.finalResult();
}

fn expectGroupedArena(commitment: *const production.MainCommitment) !void {
    const arena = commitment.backingBuffers().?[0];
    var next = [_]?[*]const M31{null} ** @bitSizeOf(usize);
    for (commitment.columns) |column| {
        const start = @intFromPtr(column.values.ptr);
        const arena_start = @intFromPtr(arena.ptr);
        const arena_end = @intFromPtr(arena.ptr + arena.len);
        try std.testing.expect(start >= arena_start and start < arena_end);
        if (next[column.log_size]) |expected| {
            try std.testing.expectEqual(expected, column.values.ptr);
        }
        next[column.log_size] = column.values.ptr + column.values.len;
    }
}

fn appendTreeRows(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(merkle_node.NodeRow),
    tree: @import("../air/memory_commitment/sparse_merkle.zig").Tree,
) !void {
    for (tree.nodes) |node| {
        try rows.append(allocator, merkle_node.NodeRow.fromNode(node, tree.root));
    }
}

fn appendTreeCalls(
    allocator: std.mem.Allocator,
    calls: *std.ArrayList(poseidon2_air.Call),
    tree: @import("../air/memory_commitment/sparse_merkle.zig").Tree,
) !void {
    for (tree.nodes) |node| {
        const row = merkle_node.NodeRow.fromNode(node, tree.root);
        try calls.append(allocator, row.poseidonCall());
    }
}
