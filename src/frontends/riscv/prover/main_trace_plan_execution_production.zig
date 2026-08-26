//! Production binding for the prepared seven-wave Tree-1 executor.
//!
//! All payload, placement, classification, and lookup-counter storage is
//! acquired by `prepare`. The graph callbacks contain no allocator and write
//! only coordinator-assigned final or retained destinations.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const component_order = @import("../air/component_order.zig");
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_boundary = @import("../air/memory_commitment/boundary.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_commitment = @import("../air/program/commitment.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
const guest_lookup_registration =
    @import("../air/guest_precompile/lookup_registration.zig");
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const execution = @import("main_trace_plan_execution.zig");
const arena_mod = @import("main_trace_plan_execution_production_arena.zig");
const generators = @import("main_trace_plan_execution_production_generators.zig");
const main_witness_work = @import("main_witness_work.zig");
const poseidon_witness_work = @import("poseidon_witness_work.zig");
const plan_mod = @import("main_trace_plan.zig");
const geometry_mod = @import("statement_geometry.zig");

pub const MAX_LOG_SIZES = @bitSizeOf(usize);
pub const MAX_COMPONENTS = statement_mod.MAX_COMPONENTS;
pub const MAX_INFRA = statement_mod.MAX_INFRA_COMPONENTS;

pub const Inputs = struct {
    execution_trace: *const trace_mod.Trace,
    witness: *const commitment_witness.CommitmentWitness,
    geometry: geometry_mod.Geometry,
    state_chain: ?*const state_chain.StateChainTracker,
    poseidon2_caller_lookup: ?Poseidon2CallerLookupInput = null,
    capture_main_witness_work: bool = false,
};

pub const Poseidon2CallerLookupInput = struct {
    extension: *const guest_statement.ExtensionStatement,
    columns: guest_lookup_registration.CallerMainColumns,
    log_size: u32,
    n_rows: u32,
};

pub const MainCommitment = arena_mod.Commitment;

/// A non-copyable owner of the production kernel and its structural epoch.
pub const Prepared = struct {
    state: *State,
    epoch: execution.PreparedEpoch,

    pub fn prepare(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
    ) !Prepared {
        return prepareWithDestinationPolicy(
            allocator,
            plan,
            statement,
            inputs,
            .grouped_backing,
        );
    }

    /// Production entrypoint. The engine's backend capability decides whether
    /// Tree 1 is built in independently owned CPU columns or in one aligned
    /// backing allocation that the commitment backend can adopt without copy.
    pub fn prepareForEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
    ) !Prepared {
        return prepareWithDestinationPolicy(
            allocator,
            plan,
            statement,
            inputs,
            arena_mod.DestinationPolicy.forEngine(Engine),
        );
    }

    /// Extension-aware counterpart for a plan whose ordinary row count was
    /// authenticated by `main_trace_plan.buildPoseidon2`.
    pub fn preparePoseidon2ForEngine(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
        counts: plan_mod.Poseidon2ExecutionCounts,
        inputs: Inputs,
    ) !Prepared {
        try plan_mod.validatePoseidon2(plan, statement, extension, counts);
        if (inputs.poseidon2_caller_lookup) |guest_lookup| {
            try validatePoseidon2CallerLookupInput(extension, &guest_lookup);
        } else if (extension.counts.n_guest != 0) {
            return error.InvalidProductionInput;
        }
        return prepareWithDestinationPolicyValidated(
            allocator,
            plan,
            statement,
            inputs,
            arena_mod.DestinationPolicy.forEngine(Engine),
        );
    }

    pub fn prepareWithDestinationPolicy(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
        destination_policy: arena_mod.DestinationPolicy,
    ) !Prepared {
        // The base entrypoint must never silently admit extension lookup
        // effects. Even a structurally valid caller input requires the
        // extension-aware cardinality binding above.
        if (inputs.poseidon2_caller_lookup != null)
            return error.InvalidProductionInput;
        try plan_mod.validate(plan, statement);
        return prepareWithDestinationPolicyValidated(
            allocator,
            plan,
            statement,
            inputs,
            destination_policy,
        );
    }

    fn prepareWithDestinationPolicyValidated(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
        destination_policy: arena_mod.DestinationPolicy,
    ) !Prepared {
        const state = try State.init(
            allocator,
            plan,
            statement,
            inputs,
            destination_policy,
        );
        errdefer state.deinit();
        var epoch = try execution.PreparedEpoch.prepare(allocator, plan, .{
            .context = state,
            .run = State.run,
        });
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

    /// Exact producer-owned work published by the successful Tree-1 seal.
    pub fn mainWitnessWorkReceipt(
        self: *const Prepared,
    ) !main_witness_work.Receipt {
        try self.requirePublished();
        const work = self.state.work orelse
            return error.MainWitnessWorkReceiptNotCaptured;
        return work.receipt orelse
            error.MainWitnessWorkReceiptNotCaptured;
    }

    /// Exact sparse-tree and base Poseidon2 work published by the successful
    /// Tree-1 seal. The upstream witness builder owns site planning; this
    /// prepared owner only closes the producer receipt chain it was given.
    pub fn poseidonWitnessWorkReceipt(
        self: *const Prepared,
    ) !poseidon_witness_work.Receipt {
        try self.requirePublished();
        const work = self.state.poseidon_work orelse
            return error.PoseidonWorkReceiptNotCaptured;
        return work.receipt orelse
            error.PoseidonWorkReceiptNotCaptured;
    }

    pub fn requestCancellation(self: *Prepared) bool {
        return self.epoch.requestCancellation();
    }

    pub fn mainColumns(
        self: *const Prepared,
    ) ![]const @import("stwo_prover_engine").pcs.ColumnEvaluation {
        try self.requirePublished();
        if (self.state.artifacts.columns.len == 0) {
            return error.Tree1ProductionOutputAlreadyTransferred;
        }
        return self.state.artifacts.columns;
    }

    /// Moves final Tree-1 storage to the commitment engine without allocating
    /// or copying. Retained opcode and clock buffers remain borrowed through
    /// this prepared owner for Tree 2.
    pub fn takeMainCommitment(self: *Prepared) !MainCommitment {
        try self.requirePublished();
        return self.state.artifacts.takeCommitment();
    }

    pub fn retainedOpcodeColumn(
        self: *const Prepared,
        component_index: usize,
        column_index: usize,
    ) ![]const M31 {
        try self.requirePublished();
        if (component_index >= self.state.statement.n_components or
            column_index >= self.state.statement.component_descs[component_index].n_columns)
        {
            return error.InvalidProductionDestinationShape;
        }
        return self.state.retained_opcode[component_index][column_index];
    }

    /// Statement identity authenticated by this prepared owner.
    ///
    /// Tree 2 uses pointer identity, not a by-value structural comparison, to
    /// prevent retained columns from one proving transaction being paired with
    /// an equal-looking statement owned by another transaction.
    pub fn retainedStatement(
        self: *const Prepared,
    ) !*const statement_mod.RiscVStatement {
        try self.requirePublished();
        return self.state.statement;
    }

    /// Number of ordinary RISC-V retirements authenticated by this Tree-1
    /// owner. Split extension finishers use the value to reject an equal
    /// statement paired with a base plan built for different row semantics.
    pub fn retainedOrdinarySteps(self: *const Prepared) !u32 {
        try self.requirePublished();
        return self.state.plan.ordinary_steps;
    }

    pub fn retainedClockColumn(
        self: *const Prepared,
        column_index: usize,
    ) ![]const M31 {
        try self.requirePublished();
        if (column_index >= infra.CLOCK_UPDATE_COLS) {
            return error.InvalidProductionDestinationShape;
        }
        return self.state.retained_clock[column_index];
    }

    /// Borrows the canonical reduced-and-seeded lookup counter used to write
    /// Tree 1's multiplicity column. Ownership remains with `Prepared` until
    /// every Tree-2 and composition borrower has finished.
    pub fn retainedLookupCounter(
        self: *const Prepared,
        kind: lookup_schema.Kind,
    ) !*const lookup_counter.Counter {
        try self.requirePublished();
        if (self.state.initialized_counters != 1) {
            return error.InvalidProductionLookupAuthority;
        }
        const counter = &self.state.chunk_counters[0].counters[@intFromEnum(kind)];
        if (counter.kind != kind or counter.values.len != lookup_schema.size(kind)) {
            return error.InvalidProductionLookupAuthority;
        }
        return counter;
    }

    fn requirePublished(self: *const Prepared) !void {
        if (self.epoch.lifecycle() != .published or
            !self.state.sealed.load(.acquire))
        {
            return error.Tree1ProductionOutputNotPublished;
        }
    }
};

fn validatePoseidon2CallerLookupInput(
    extension: *const guest_statement.ExtensionStatement,
    input: *const Poseidon2CallerLookupInput,
) !void {
    if (input.extension != extension or
        input.n_rows != extension.counts.n_guest or
        input.log_size != extension.components[0].log_size or
        input.log_size >= @bitSizeOf(usize))
    {
        return error.InvalidProductionInput;
    }
    const domain_size = @as(usize, 1) << @intCast(input.log_size);
    if (@as(usize, input.n_rows) > domain_size)
        return error.InvalidProductionInput;
    for (input.columns) |column| {
        if (column.len != domain_size) return error.InvalidProductionInput;
    }
}

/// Profiling-only storage. Ordinary proofs retain one null pointer in `State`
/// and neither allocate nor zero these ~300 KiB of race-free receipt shards.
pub const WorkState = struct {
    authority: main_witness_work.Authority,
    opcode: [work_pool.MAX_WORKERS]main_witness_work.Shard,
    infrastructure: [MAX_INFRA]main_witness_work.Shard,
    audit: [MAX_COMPONENTS]main_witness_work.Shard,
    reduction: main_witness_work.Shard,
    seed: main_witness_work.Shard,
    receipt: ?main_witness_work.Receipt,

    pub fn init(allocator: std.mem.Allocator) !*WorkState {
        const self = try allocator.create(WorkState);
        errdefer allocator.destroy(self);
        self.* = .{
            .authority = try main_witness_work.Authority.init(),
            .opcode = .{main_witness_work.Shard{}} ** work_pool.MAX_WORKERS,
            .infrastructure = .{main_witness_work.Shard{}} ** MAX_INFRA,
            .audit = .{main_witness_work.Shard{}} ** MAX_COMPONENTS,
            .reduction = .{},
            .seed = .{},
            .receipt = null,
        };
        return self;
    }

    pub fn deinit(self: *WorkState, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

/// Profiling-only aggregation for the producer receipts split across the
/// sparse-tree witness builder and disjoint Poseidon2 row chunks. Ordinary
/// proofs retain one null pointer and execute the pre-existing hot loops.
pub const PoseidonWorkState = struct {
    authority: poseidon_witness_work.Authority,
    initial: poseidon_witness_work.Shard,
    chunks: [work_pool.MAX_WORKERS]?poseidon_witness_work.ProducerReceipt,
    receipt: ?poseidon_witness_work.Receipt,

    pub fn init(
        allocator: std.mem.Allocator,
        initial: poseidon_witness_work.Shard,
    ) !*PoseidonWorkState {
        const self = try allocator.create(PoseidonWorkState);
        errdefer allocator.destroy(self);
        const authority = poseidon_witness_work.Authority.init();
        try initial.validate(&authority);
        if (initial.counts.base_air_rows != 0 or
            initial.counts.guest_provider_preflight_rows != 0 or
            initial.counts.guest_provider_materialization_rows != 0 or
            initial.counts.legacy_common_traces != 0)
        {
            return error.InvalidPoseidonWorkReceipt;
        }
        self.* = .{
            .authority = authority,
            .initial = initial,
            .chunks = .{null} ** work_pool.MAX_WORKERS,
            .receipt = null,
        };
        return self;
    }

    pub fn deinit(self: *PoseidonWorkState, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

const State = @import("main_trace_plan_execution_production_state.zig").makeState(@This());

pub fn expectedAdd(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.MainWitnessWorkOverflow;
}

comptime {
    if (component_order.LOOKUP_TABLE_COUNT != lookup_schema.KIND_COUNT) {
        @compileError("Tree-1 lookup task and counter counts diverged");
    }
}
