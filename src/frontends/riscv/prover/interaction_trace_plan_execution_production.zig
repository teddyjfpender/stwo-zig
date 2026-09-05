//! Production binding for the prepared three-wave Tree-2 executor.
//!
//! The coordinator admits the complete resident byte set, allocates every
//! destination and batch-inversion buffer, and binds each statement descriptor
//! to one immutable output/claim range before a worker can start. Leaf tasks
//! receive disjoint scratch because they may overlap. Pool-exclusive tasks
//! borrow one maximum-sized scratch region because the task-graph executor
//! drains all other work before exposing the retained lease.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

const clock_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_entry = @import("../air/lookups/entry.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const BaseScalar = @import("../air/lookups/base_scalar.zig").Scalar;
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");
const logup = @import("../air/logup.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const plan_mod = @import("interaction_trace_plan.zig");
const execution = @import("interaction_trace_plan_execution.zig");
const prepared_logup = @import("interaction_trace_prepared_logup.zig");
const interaction_witness_work = @import("interaction_witness_work.zig");
const geometry_mod = @import("statement_geometry.zig");
const tree2_main_source = @import("tree2_main_source.zig");

pub const MAX_LOG_SIZES = @bitSizeOf(usize);
pub const MAX_DESCRIPTORS = plan_mod.MAX_DESCRIPTORS;
pub const MAX_COLUMNS_PER_DESCRIPTOR = opcode_interaction.MAX_COLUMNS;
pub const MAX_SUMS = opcode_interaction.MAX_BATCHES;
const OpcodeBaseEntries = opcode_entries.Entries(BaseScalar);
const OpcodeBaseList = lookup_entry.Builder(BaseScalar).List;
const OpcodeBaseEntry = lookup_entry.Builder(BaseScalar).Entry;

pub const Inputs = struct {
    witness: *const commitment_witness.CommitmentWitness,
    geometry: geometry_mod.Geometry,
    main_source: tree2_main_source.Source,
    relations: *const relation_challenges.Relations,
    claim: *statement_mod.RiscVInteractionClaim,
};

pub const WorkInputs = struct {
    authority: interaction_witness_work.Authority,
    session_digest: interaction_witness_work.Digest,
    challenge_receipt: interaction_witness_work.ProducerReceipt,
};

/// Non-copyable owner of every prepared Tree-2 destination and kernel buffer.
pub const Prepared = struct {
    state: *State,
    epoch: execution.PreparedEpoch,

    pub fn prepare(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
        request: prover_api.CpuCompositionExecutionRequest,
        pool_capacity: usize,
        worker_stack_bytes: usize,
    ) !Prepared {
        return prepareWithOrdinarySteps(
            allocator,
            statement,
            statement.total_steps,
            inputs,
            request,
            pool_capacity,
            worker_stack_bytes,
        );
    }

    pub fn prepareWithOrdinarySteps(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        ordinary_steps: u32,
        inputs: Inputs,
        request: prover_api.CpuCompositionExecutionRequest,
        pool_capacity: usize,
        worker_stack_bytes: usize,
    ) !Prepared {
        return prepareInternal(
            allocator,
            statement,
            ordinary_steps,
            inputs,
            request,
            pool_capacity,
            worker_stack_bytes,
            null,
            false,
        );
    }

    /// Profiling-only sibling. Its callback derives one descriptor receipt
    /// after each normal producer completes and seals them with the challenge
    /// receipt at the existing Tree-2 seal wave.
    pub fn prepareWithWorkReceipt(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
        request: prover_api.CpuCompositionExecutionRequest,
        pool_capacity: usize,
        worker_stack_bytes: usize,
        work_inputs: WorkInputs,
    ) !Prepared {
        return prepareInternal(
            allocator,
            statement,
            statement.total_steps,
            inputs,
            request,
            pool_capacity,
            worker_stack_bytes,
            work_inputs,
            true,
        );
    }

    fn prepareInternal(
        allocator: std.mem.Allocator,
        statement: *const statement_mod.RiscVStatement,
        ordinary_steps: u32,
        inputs: Inputs,
        request: prover_api.CpuCompositionExecutionRequest,
        pool_capacity: usize,
        worker_stack_bytes: usize,
        work_inputs: ?WorkInputs,
        comptime capture_work: bool,
    ) !Prepared {
        // The first derivation is pure and deliberately unbudgeted. It resolves
        // worker admission and canonical descriptor classes, which determine
        // the exact shared-scratch shape used by the budgeted final plan.
        var shape_request = request;
        shape_request.host_byte_budget = std.math.maxInt(usize);
        const shape_plan = try plan_mod.buildForOrdinarySteps(statement, ordinary_steps, .{
            .execution = shape_request,
            .pool_capacity = pool_capacity,
            .worker_stack_bytes = worker_stack_bytes,
            .retained_input_bytes = 0,
            .prepared_generator_bytes = 0,
        });
        var shape = try ResourceShape.deriveForOrdinarySteps(
            statement,
            &shape_plan,
            ordinary_steps,
        );
        if (capture_work) {
            shape = try shape.withWorkProfile(shape_plan.descriptor_count);
        }
        const retained_bytes = try retainedInputBytes(statement, inputs);
        const final_plan = try plan_mod.buildForOrdinarySteps(statement, ordinary_steps, .{
            .execution = request,
            .pool_capacity = pool_capacity,
            .worker_stack_bytes = worker_stack_bytes,
            .retained_input_bytes = retained_bytes,
            .prepared_generator_bytes = shape.prepared_bytes,
        });

        const state = try State.init(
            allocator,
            &final_plan,
            statement,
            inputs,
            shape,
            ordinary_steps,
            work_inputs,
        );
        errdefer state.deinit();
        var epoch = try execution.PreparedEpoch.prepareForOrdinarySteps(
            allocator,
            &final_plan,
            statement,
            ordinary_steps,
            .{
                .context = state,
                .run = if (capture_work) State.runProfiled else State.run,
            },
        );
        errdefer epoch.deinit();
        return .{ .state = state, .epoch = epoch };
    }

    pub fn deinit(self: *Prepared) void {
        self.epoch.deinit();
        self.state.deinit();
        self.* = undefined;
    }

    pub fn execute(
        self: *Prepared,
        pool: ?*work_pool.WorkPool,
    ) !execution.EpochReport {
        return self.epoch.execute(pool);
    }

    pub fn requestCancellation(self: *Prepared) bool {
        return self.epoch.requestCancellation();
    }

    /// Test-only borrowed view at the exact post-publication, pre-transfer
    /// boundary used to exercise committed Tree-2 forgery rejection. Ownership
    /// remains with this prepared state; production callers never need this.
    pub fn borrowPublishedColumnsForTest(
        self: *Prepared,
    ) ![]prover_pcs.ColumnEvaluation {
        if (self.epoch.lifecycle() != .published or
            !self.state.sealed.load(.acquire))
        {
            return error.Tree2ProductionOutputNotPublished;
        }
        if (self.state.columns.len == 0) {
            return error.Tree2ProductionOutputAlreadyTransferred;
        }
        return self.state.columns;
    }

    /// Transfers exact CPU-owned column allocations to the commitment engine.
    /// No copy or allocation occurs at this boundary.
    pub fn takeColumns(self: *Prepared) ![]prover_pcs.ColumnEvaluation {
        if (self.epoch.lifecycle() != .published or
            !self.state.sealed.load(.acquire))
        {
            return error.Tree2ProductionOutputNotPublished;
        }
        if (self.state.columns.len == 0) {
            return error.Tree2ProductionOutputAlreadyTransferred;
        }
        const result = self.state.columns;
        self.state.columns = &.{};
        self.state.initialized_columns = 0;
        return result;
    }

    pub fn plan(self: *const Prepared) *const plan_mod.Plan {
        return &self.state.plan;
    }

    pub fn interactionWorkReceipt(
        self: *const Prepared,
    ) !interaction_witness_work.Receipt {
        if (self.epoch.lifecycle() != .published or
            !self.state.sealed.load(.acquire))
        {
            return error.Tree2ProductionOutputNotPublished;
        }
        const work = self.state.work orelse
            return error.InteractionWorkReceiptUnavailable;
        return work.receipt orelse error.InteractionWorkReceiptUnavailable;
    }
};

pub const ResourceShape = struct {
    placement_cells: usize,
    summary_cells: usize,
    error_slots: usize,
    scratch_cells: usize,
    prepared_bytes: usize,

    fn derive(
        statement: *const statement_mod.RiscVStatement,
        plan: *const plan_mod.Plan,
    ) !ResourceShape {
        try plan_mod.validate(plan, statement);
        return deriveValidated(statement, plan);
    }

    pub fn deriveForOrdinarySteps(
        statement: *const statement_mod.RiscVStatement,
        plan: *const plan_mod.Plan,
        ordinary_steps: u32,
    ) !ResourceShape {
        try plan_mod.validateForOrdinarySteps(plan, statement, ordinary_steps);
        return deriveValidated(statement, plan);
    }

    fn deriveValidated(
        statement: *const statement_mod.RiscVStatement,
        plan: *const plan_mod.Plan,
    ) !ResourceShape {
        var seen_logs = [_]bool{false} ** MAX_LOG_SIZES;
        var placement_cells: usize = 0;
        var leaf_summary: usize = 0;
        var pool_summary: usize = 0;
        var leaf_errors: usize = 0;
        var pool_errors: usize = 0;
        var leaf_scratch: usize = 0;
        var pool_scratch: usize = 0;

        for (0..@as(usize, plan.descriptor_count)) |registry_index| {
            const facts = try descriptorFacts(statement, plan, registry_index);
            if (!seen_logs[facts.log_size]) {
                seen_logs[facts.log_size] = true;
                placement_cells = try checkedAdd(placement_cells, facts.trace_size);
            }
            const summary = try checkedMul(
                try checkedMul(facts.chunk_count, facts.n_sums),
                2,
            );
            const scratch = try checkedMul(
                try checkedMul(
                    try checkedMul(facts.lane_count, 3),
                    facts.n_sums,
                ),
                facts.chunk_capacity,
            );
            switch (facts.class) {
                .leaf => {
                    leaf_summary = try checkedAdd(leaf_summary, summary);
                    leaf_errors = try checkedAdd(leaf_errors, facts.chunk_count);
                    leaf_scratch = try checkedAdd(leaf_scratch, scratch);
                },
                .pool_exclusive => {
                    pool_summary = @max(pool_summary, summary);
                    pool_errors = @max(pool_errors, facts.chunk_count);
                    pool_scratch = @max(pool_scratch, scratch);
                },
                .coordinator => return error.InvalidTree2ProductionClass,
            }
        }

        const summary_cells = try checkedAdd(leaf_summary, pool_summary);
        const error_slots = try checkedAdd(leaf_errors, pool_errors);
        const scratch_cells = try checkedAdd(leaf_scratch, pool_scratch);
        var prepared_bytes: usize = @sizeOf(State);
        prepared_bytes = try checkedAdd(
            prepared_bytes,
            try checkedMul(plan.descriptor_count, @sizeOf(prepared_logup.Storage)),
        );
        prepared_bytes = try checkedAdd(
            prepared_bytes,
            try checkedMul(placement_cells, @sizeOf(usize)),
        );
        prepared_bytes = try checkedAdd(
            prepared_bytes,
            try checkedMul(summary_cells, @sizeOf(QM31)),
        );
        prepared_bytes = try checkedAdd(
            prepared_bytes,
            try checkedMul(error_slots, @sizeOf(?anyerror)),
        );
        prepared_bytes = try checkedAdd(
            prepared_bytes,
            try checkedMul(scratch_cells, @sizeOf(QM31)),
        );
        return .{
            .placement_cells = placement_cells,
            .summary_cells = summary_cells,
            .error_slots = error_slots,
            .scratch_cells = scratch_cells,
            .prepared_bytes = prepared_bytes,
        };
    }

    /// Profiling owns one fixed request state plus one optional receipt slot
    /// per immutable descriptor. Account both before admission so enabling
    /// exact work capture cannot allocate outside the caller's host budget.
    pub fn withWorkProfile(
        self: ResourceShape,
        descriptor_count: u16,
    ) !ResourceShape {
        var result = self;
        result.prepared_bytes = try checkedAdd(
            result.prepared_bytes,
            @sizeOf(WorkState),
        );
        result.prepared_bytes = try checkedAdd(
            result.prepared_bytes,
            try checkedMul(
                descriptor_count,
                @sizeOf(?interaction_witness_work.ProducerReceipt),
            ),
        );
        return result;
    }
};

pub const DescriptorFacts = struct {
    class: task_graph.TaskClass,
    log_size: u32,
    trace_size: usize,
    n_sums: usize,
    chunk_count: usize,
    chunk_capacity: usize,
    lane_count: usize,
};

pub const WorkState = struct {
    authority: interaction_witness_work.Authority,
    session_digest: interaction_witness_work.Digest,
    completed: interaction_witness_work.Shard,
    descriptor_receipts: []?interaction_witness_work.ProducerReceipt,
    receipt: ?interaction_witness_work.Receipt = null,
};

pub fn descriptorFacts(
    statement: *const statement_mod.RiscVStatement,
    plan: *const plan_mod.Plan,
    registry_index: usize,
) !DescriptorFacts {
    const class = plan.descriptorClass(registry_index) orelse
        return error.InvalidTree2ProductionDescriptor;
    const range = plan.descriptorColumnRange(registry_index) orelse
        return error.InvalidTree2ProductionDescriptor;
    if (range.len == 0 or range.len % 4 != 0) {
        return error.InvalidTree2ProductionDescriptor;
    }
    const log_size = if (registry_index < statement.n_components)
        statement.component_descs[registry_index].log_size
    else
        statement.infra_descs[registry_index - statement.n_components].log_size;
    if (log_size >= MAX_LOG_SIZES) return error.Tree2ResourceOverflow;
    const trace_size = @as(usize, 1) << @intCast(log_size);
    const chunk_count = std.math.divCeil(
        usize,
        trace_size,
        prepared_logup.CHUNK_ROWS,
    ) catch unreachable;
    const lane_count = if (class == .pool_exclusive)
        @min(@as(usize, plan.planned_worker_count), chunk_count)
    else
        1;
    return .{
        .class = class,
        .log_size = log_size,
        .trace_size = trace_size,
        .n_sums = range.len / 4,
        .chunk_count = chunk_count,
        .chunk_capacity = @min(trace_size, prepared_logup.CHUNK_ROWS),
        .lane_count = lane_count,
    };
}

const State = @import("interaction_trace_plan_execution_production_state.zig").makeState(@This());

pub const SharedOffsets = struct { summary: usize, errors: usize, scratch: usize };

pub fn sharedOffsets(
    statement: *const statement_mod.RiscVStatement,
    plan: *const plan_mod.Plan,
) !SharedOffsets {
    var result = SharedOffsets{ .summary = 0, .errors = 0, .scratch = 0 };
    for (0..@as(usize, plan.descriptor_count)) |registry_index| {
        const facts = try descriptorFacts(statement, plan, registry_index);
        if (facts.class != .leaf) continue;
        result.summary = try checkedAdd(
            result.summary,
            try checkedMul(try checkedMul(facts.chunk_count, facts.n_sums), 2),
        );
        result.errors = try checkedAdd(result.errors, facts.chunk_count);
        result.scratch = try checkedAdd(
            result.scratch,
            try checkedMul(
                try checkedMul(try checkedMul(facts.lane_count, 3), facts.n_sums),
                facts.chunk_capacity,
            ),
        );
    }
    return result;
}

pub const OpcodeRows = struct {
    family: trace_mod.OpcodeFamily,
    columns: []const []const M31,
    relations: *const relation_challenges.Relations,
    n_sums: usize,

    pub fn rowPairsAt(
        self: @This(),
        _: usize,
        committed_row: usize,
    ) ![MAX_SUMS]logup.RowPair {
        var base: [trace_mod.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
        for (self.columns, base[0..self.columns.len]) |column, *value| {
            value.* = BaseScalar.fromBase(column[committed_row]);
        }
        const list = try OpcodeBaseEntries.fromMain(
            self.family,
            base[0..self.columns.len],
        );
        if (list.batchCount() != self.n_sums) return error.InvalidBatchCount;
        var result: [MAX_SUMS]logup.RowPair = undefined;
        for (result[0..self.n_sums], 0..) |*pair, batch| {
            pair.* = try opcodePair(&list, batch, self.relations);
        }
        return result;
    }
};

pub const ProgramRows = struct {
    rows: []const program_commitment.Row,
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(self: @This(), logical_row: usize, _: usize) ![program_interaction.N_SUMS]logup.RowPair {
        return if (logical_row < self.rows.len)
            program_interaction.rowPairsFromRow(self.rows[logical_row], self.relations)
        else
            program_interaction.paddingPairs();
    }
};

pub const MemoryRows = struct {
    rows: []const memory_boundary.Row,
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(self: @This(), logical_row: usize, _: usize) ![memory_interaction.N_SUMS]logup.RowPair {
        return if (logical_row < self.rows.len)
            memory_interaction.rowPairs(self.rows[logical_row], self.relations)
        else
            memory_interaction.paddingPairs(self.relations);
    }
};

pub const MerkleRows = struct {
    rows: []const merkle_node.NodeRow,
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(self: @This(), logical_row: usize, _: usize) ![merkle_node.N_SUMS]logup.RowPair {
        return if (logical_row < self.rows.len)
            merkle_node.rowPairsFromNode(self.rows[logical_row], self.relations)
        else
            merkle_node.paddingPairs();
    }
};

pub const PoseidonRows = struct {
    calls: []const poseidon2_air.Call,
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(self: @This(), logical_row: usize, _: usize) ![poseidon2_air.N_SUMS]logup.RowPair {
        return if (logical_row < self.calls.len)
            poseidon2_air.rowPairsFromCall(self.calls[logical_row], self.relations)
        else
            poseidon2_air.paddingPairs();
    }
};

pub const ClockRows = struct {
    columns: [clock_interaction.N_MAIN_COLUMNS][]const M31,
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(
        self: @This(),
        _: usize,
        committed_row: usize,
    ) ![clock_interaction.N_SUMS]logup.RowPair {
        var sampled: [clock_interaction.N_MAIN_COLUMNS]QM31 = undefined;
        for (self.columns, &sampled) |column, *value| {
            value.* = QM31.fromBase(column[committed_row]);
        }
        return clock_interaction.pairs(
            try clock_interaction.Row.fromMain(&sampled),
            self.relations,
        );
    }
};

pub const TableRows = struct {
    kind: lookup_schema.Kind,
    counter: *const lookup_counter.Counter,
    relations: *const relation_challenges.Relations,

    pub fn rowPairsAt(self: @This(), logical_row: usize, _: usize) ![1]logup.RowPair {
        return .{try table_interaction.rowPair(
            self.kind,
            try lookup_schema.tupleAt(self.kind, logical_row),
            self.counter.values[logical_row],
            self.relations,
        )};
    }
};

pub fn opcodePair(
    list: *const OpcodeBaseList,
    batch: usize,
    relations: *const relation_challenges.Relations,
) !logup.RowPair {
    const first = &list.entries[batch * list.batch_size];
    const first_numerator = QM31.fromBase(first.numerator.value);
    if (list.batch_size == 1 or batch * list.batch_size + 1 == list.len) {
        return logup.RowPair.single(
            first_numerator,
            try opcodeDenominator(first, relations),
        );
    }
    const second = &list.entries[batch * list.batch_size + 1];
    return .{
        .n1 = first_numerator,
        .d1 = try opcodeDenominator(first, relations),
        .n2 = QM31.fromBase(second.numerator.value),
        .d2 = try opcodeDenominator(second, relations),
    };
}

pub fn opcodeDenominator(
    relation_entry: *const OpcodeBaseEntry,
    relations: *const relation_challenges.Relations,
) !QM31 {
    try relation_entry.validate();
    return switch (relation_entry.domain) {
        .registers_state => relations.registers_state.combineBase(unwrapBase(2, relation_entry.values[0..2].*)),
        .memory_access => relations.memory_access.combineBase(unwrapBase(7, relation_entry.values[0..7].*)),
        .program_access => relations.program_access.combineBase(unwrapBase(5, relation_entry.values[0..5].*)),
        .merkle => relations.merkle.combineBase(unwrapBase(4, relation_entry.values[0..4].*)),
        .poseidon2 => relations.poseidon2.combineBase(unwrapBase(16, relation_entry.values[0..16].*)),
        .poseidon2_io => relations.poseidon2_io.combineBase(unwrapBase(32, relation_entry.values[0..32].*)),
        .bitwise => relations.bitwise.combineBase(unwrapBase(4, relation_entry.values[0..4].*)),
        .range_check_20 => relations.range_check_20.combineBase(unwrapBase(1, relation_entry.values[0..1].*)),
        .range_check_8_11 => relations.range_check_8_11.combineBase(unwrapBase(2, relation_entry.values[0..2].*)),
        .range_check_8_8_4 => relations.range_check_8_8_4.combineBase(unwrapBase(3, relation_entry.values[0..3].*)),
        .range_check_8_8 => relations.range_check_8_8.combineBase(unwrapBase(2, relation_entry.values[0..2].*)),
        .range_check_m31 => relations.range_check_m31.combineBase(unwrapBase(2, relation_entry.values[0..2].*)),
    };
}

pub fn unwrapBase(comptime n: usize, values: [n]BaseScalar) [n]M31 {
    var result: [n]M31 = undefined;
    for (values, &result) |value, *destination| destination.* = value.value;
    return result;
}

pub fn validateInputs(
    statement: *const statement_mod.RiscVStatement,
    inputs: Inputs,
) !void {
    try inputs.main_source.validate(statement);
    if (inputs.claim.n_components != statement.n_components or
        inputs.claim.n_infra != statement.n_infra)
    {
        return error.InvalidTree2ProductionClaim;
    }
    if (statement.infra_descs[0].kind != .program or
        statement.infra_descs[0].n_rows != inputs.witness.program.rows.len or
        inputs.geometry.program_log_size != statement.infra_descs[0].log_size or
        inputs.geometry.merkle_infra_index >= statement.n_infra or
        inputs.geometry.poseidon_infra_index >= statement.n_infra or
        inputs.geometry.clock_infra_index >= statement.n_infra)
    {
        return error.InvalidTree2ProductionInput;
    }
    const merkle = statement.infra_descs[inputs.geometry.merkle_infra_index];
    const poseidon = statement.infra_descs[inputs.geometry.poseidon_infra_index];
    const clock = statement.infra_descs[inputs.geometry.clock_infra_index];
    if (merkle.kind != .merkle or merkle.n_rows != inputs.witness.merkleRows().len or
        merkle.log_size != inputs.geometry.merkle_log_size or
        poseidon.kind != .poseidon2 or poseidon.n_rows != inputs.witness.poseidonCalls().len or
        poseidon.log_size != inputs.geometry.poseidon_log_size or
        clock.kind != .clock_update or clock.log_size != inputs.geometry.clock_update_log)
    {
        return error.InvalidTree2ProductionInput;
    }
}

pub fn retainedInputBytes(
    statement: *const statement_mod.RiscVStatement,
    inputs: Inputs,
) !usize {
    var result: usize = @sizeOf(statement_mod.RiscVStatement);
    result = try checkedAdd(result, @sizeOf(commitment_witness.CommitmentWitness));
    result = try checkedAdd(result, @sizeOf(tree2_main_source.Source));
    result = try checkedAdd(result, @sizeOf(relation_challenges.Relations));

    for (statement.component_descs[0..statement.n_components]) |desc| {
        const cells = try checkedMul(
            @as(usize, 1) << @intCast(desc.log_size),
            desc.n_columns,
        );
        result = try checkedAdd(result, try checkedMul(cells, @sizeOf(M31)));
    }
    const clock_desc = statement.infra_descs[inputs.geometry.clock_infra_index];
    result = try checkedAdd(
        result,
        try checkedMul(
            try checkedMul(
                @as(usize, 1) << @intCast(clock_desc.log_size),
                clock_interaction.N_MAIN_COLUMNS,
            ),
            @sizeOf(M31),
        ),
    );
    inline for (std.meta.fields(lookup_schema.Kind)) |field| {
        const kind: lookup_schema.Kind = @enumFromInt(field.value);
        result = try checkedAdd(
            result,
            try checkedMul(lookup_schema.size(kind), @sizeOf(M31)),
        );
    }
    result = try checkedAdd(
        result,
        try checkedMul(inputs.witness.program.rows.len, @sizeOf(program_commitment.Row)),
    );
    const boundary_rows = inputs.witness.memoryBoundaryRows();
    if (boundary_rows.len != 0) {
        result = try checkedAdd(
            result,
            try checkedMul(boundary_rows.len, @sizeOf(memory_boundary.Row)),
        );
    }
    result = try checkedAdd(
        result,
        try checkedMul(inputs.witness.merkleRows().len, @sizeOf(merkle_node.NodeRow)),
    );
    result = try checkedAdd(
        result,
        try checkedMul(inputs.witness.poseidonCalls().len, @sizeOf(poseidon2_air.Call)),
    );
    return result;
}

pub fn checkedAdd(lhs: anytype, rhs: anytype) !usize {
    const left: usize = @intCast(lhs);
    const right: usize = @intCast(rhs);
    return std.math.add(usize, left, right) catch error.Tree2ResourceOverflow;
}

pub fn checkedMul(lhs: anytype, rhs: anytype) !usize {
    const left: usize = @intCast(lhs);
    const right: usize = @intCast(rhs);
    return std.math.mul(usize, left, right) catch error.Tree2ResourceOverflow;
}

pub fn checkedAddU64(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.InteractionWorkOverflow;
}

pub fn domainSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.Tree2ResourceOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

comptime {
    if (component_order.LOOKUP_TABLE_COUNT != lookup_schema.KIND_COUNT) {
        @compileError("Tree-2 lookup descriptor and counter counts diverged");
    }
    if (MAX_COLUMNS_PER_DESCRIPTOR < 16 or MAX_SUMS * 4 != MAX_COLUMNS_PER_DESCRIPTOR) {
        @compileError("Tree-2 destination capacity no longer covers all descriptors");
    }
}
