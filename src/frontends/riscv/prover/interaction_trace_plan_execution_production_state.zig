//! Production Tree-2 state machine and descriptor callbacks.
const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const prover_engine = @import("stwo_prover_engine");
const prover_pcs = prover_engine.pcs;
const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

const clock_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const BaseScalar = @import("../air/lookups/base_scalar.zig").Scalar;
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const logup = @import("../air/logup.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
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
const tree2_main_source = @import("tree2_main_source.zig");

pub fn makeState(comptime Owner: type) type {
    const Inputs = Owner.Inputs;
    const WorkInputs = Owner.WorkInputs;
    const ResourceShape = Owner.ResourceShape;
    const WorkState = Owner.WorkState;
    const MAX_LOG_SIZES = Owner.MAX_LOG_SIZES;
    const MAX_COLUMNS_PER_DESCRIPTOR = Owner.MAX_COLUMNS_PER_DESCRIPTOR;
    const MAX_SUMS = Owner.MAX_SUMS;
    const descriptorFacts = Owner.descriptorFacts;
    const sharedOffsets = Owner.sharedOffsets;
    const OpcodeRows = Owner.OpcodeRows;
    const ProgramRows = Owner.ProgramRows;
    const MemoryRows = Owner.MemoryRows;
    const MerkleRows = Owner.MerkleRows;
    const PoseidonRows = Owner.PoseidonRows;
    const ClockRows = Owner.ClockRows;
    const TableRows = Owner.TableRows;
    const checkedAdd = Owner.checkedAdd;
    const checkedMul = Owner.checkedMul;
    const checkedAddU64 = Owner.checkedAddU64;
    const domainSize = Owner.domainSize;
    const validateInputs = Owner.validateInputs;
    const OpcodeBaseEntries = opcode_entries.Entries(BaseScalar);

    return struct {
        const State = @This();

        allocator: std.mem.Allocator,
        plan: plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
        columns: []prover_pcs.ColumnEvaluation,
        initialized_columns: usize,
        ownership: []std.atomic.Value(u8),
        storages: []prepared_logup.Storage,
        placements: [MAX_LOG_SIZES]?infra.BitReversalTable,
        summary_payload: []QM31,
        error_payload: []?anyerror,
        scratch_payload: []QM31,
        memory_row_starts: [statement_mod.MAX_INFRA_COMPONENTS]usize,
        work: ?*WorkState,
        reserved: std.atomic.Value(bool) = .init(false),
        sealed: std.atomic.Value(bool) = .init(false),

        pub fn init(
            allocator: std.mem.Allocator,
            plan: *const plan_mod.Plan,
            statement: *const statement_mod.RiscVStatement,
            inputs: Inputs,
            shape: ResourceShape,
            ordinary_steps: u32,
            work_inputs: ?WorkInputs,
        ) !*State {
            try plan_mod.validateForOrdinarySteps(plan, statement, ordinary_steps);
            var expected_shape = try ResourceShape.deriveForOrdinarySteps(
                statement,
                plan,
                ordinary_steps,
            );
            if (work_inputs != null) {
                expected_shape = try expected_shape.withWorkProfile(
                    plan.descriptor_count,
                );
            }
            if (!std.meta.eql(
                expected_shape,
                shape,
            ) or
                plan.resources.prepared_generator_bytes != shape.prepared_bytes)
            {
                return error.InvalidTree2ProductionResources;
            }
            try validateInputs(statement, inputs);

            const self = try allocator.create(State);
            self.* = .{
                .allocator = allocator,
                .plan = plan.*,
                .statement = statement,
                .inputs = inputs,
                .columns = &.{},
                .initialized_columns = 0,
                .ownership = &.{},
                .storages = &.{},
                .placements = .{null} ** MAX_LOG_SIZES,
                .summary_payload = &.{},
                .error_payload = &.{},
                .scratch_payload = &.{},
                .memory_row_starts = .{0} ** statement_mod.MAX_INFRA_COMPONENTS,
                .work = null,
            };
            errdefer self.deinit();

            if (work_inputs) |selected| {
                try selected.authority.validate();
                const work = try allocator.create(WorkState);
                work.* = .{
                    .authority = selected.authority,
                    .session_digest = selected.session_digest,
                    .completed = .{},
                    .descriptor_receipts = &.{},
                };
                self.work = work;
                work.descriptor_receipts = try allocator.alloc(
                    ?interaction_witness_work.ProducerReceipt,
                    @as(usize, plan.descriptor_count),
                );
                @memset(work.descriptor_receipts, null);
                try work.completed.observe(
                    &work.authority,
                    .base,
                    work.session_digest,
                    selected.challenge_receipt,
                );
            }

            try self.prepareDestinations();
            try self.preparePlacements();
            try self.prepareStorage(shape);
            try self.prepareMemoryStarts();
            return self;
        }

        pub fn deinit(self: *State) void {
            const allocator = self.allocator;
            if (self.work) |work| {
                if (work.descriptor_receipts.len != 0)
                    allocator.free(work.descriptor_receipts);
                allocator.destroy(work);
                self.work = null;
            }
            for (&self.placements) |*placement| {
                if (placement.*) |table| table.deinit(allocator);
                placement.* = null;
            }
            if (self.scratch_payload.len != 0) allocator.free(self.scratch_payload);
            if (self.error_payload.len != 0) allocator.free(self.error_payload);
            if (self.summary_payload.len != 0) allocator.free(self.summary_payload);
            if (self.storages.len != 0) allocator.free(self.storages);
            if (self.ownership.len != 0) allocator.free(self.ownership);
            if (self.columns.len != 0) {
                for (self.columns[0..self.initialized_columns]) |column| {
                    allocator.free(@constCast(column.values));
                }
                allocator.free(self.columns);
            }
            allocator.destroy(self);
        }

        fn prepareDestinations(self: *State) !void {
            const total_columns: usize = self.plan.total_columns;
            self.columns = try self.allocator.alloc(
                prover_pcs.ColumnEvaluation,
                total_columns,
            );
            var cursor: usize = 0;
            for (0..@as(usize, self.plan.descriptor_count)) |registry_index| {
                const facts = try descriptorFacts(self.statement, &self.plan, registry_index);
                const range = self.plan.descriptorColumnRange(registry_index).?;
                if (range.start != cursor) return error.InvalidTree2ProductionDestination;
                for (0..range.len) |_| {
                    self.columns[cursor] = .{
                        .log_size = facts.log_size,
                        .values = try self.allocator.alloc(M31, facts.trace_size),
                    };
                    cursor += 1;
                    self.initialized_columns = cursor;
                }
            }
            if (cursor != total_columns) return error.InvalidTree2ProductionDestination;

            const ledger_len = try checkedAdd(
                self.plan.descriptor_count,
                try checkedAdd(self.plan.total_columns, self.plan.total_claims),
            );
            self.ownership = try self.allocator.alloc(std.atomic.Value(u8), ledger_len);
            for (self.ownership) |*slot| slot.* = .init(0);
        }

        fn preparePlacements(self: *State) !void {
            for (0..@as(usize, self.plan.descriptor_count)) |registry_index| {
                const facts = try descriptorFacts(self.statement, &self.plan, registry_index);
                if (self.placements[facts.log_size] == null) {
                    self.placements[facts.log_size] = try infra.BitReversalTable.init(
                        self.allocator,
                        facts.log_size,
                    );
                }
            }
        }

        fn prepareStorage(self: *State, shape: ResourceShape) !void {
            self.storages = try self.allocator.alloc(
                prepared_logup.Storage,
                self.plan.descriptor_count,
            );
            self.summary_payload = try self.allocator.alloc(QM31, shape.summary_cells);
            self.error_payload = try self.allocator.alloc(?anyerror, shape.error_slots);
            self.scratch_payload = try self.allocator.alloc(QM31, shape.scratch_cells);

            const shared = try sharedOffsets(self.statement, &self.plan);
            var leaf_summary: usize = 0;
            var leaf_errors: usize = 0;
            var leaf_scratch: usize = 0;
            for (self.storages, 0..) |*storage, registry_index| {
                const facts = try descriptorFacts(self.statement, &self.plan, registry_index);
                const summary_len = 2 * facts.chunk_count * facts.n_sums;
                const error_len = facts.chunk_count;
                const scratch_len = facts.lane_count * 3 * facts.n_sums * facts.chunk_capacity;
                const summary_start = if (facts.class == .leaf) blk: {
                    const start = leaf_summary;
                    leaf_summary += summary_len;
                    break :blk start;
                } else shared.summary;
                const error_start = if (facts.class == .leaf) blk: {
                    const start = leaf_errors;
                    leaf_errors += error_len;
                    break :blk start;
                } else shared.errors;
                const scratch_start = if (facts.class == .leaf) blk: {
                    const start = leaf_scratch;
                    leaf_scratch += scratch_len;
                    break :blk start;
                } else shared.scratch;
                const half = summary_len / 2;
                storage.* = .{
                    .trace_size = facts.trace_size,
                    .n_sums = facts.n_sums,
                    .lane_count = facts.lane_count,
                    .chunk_totals = self.summary_payload[summary_start .. summary_start + half],
                    .chunk_offsets = self.summary_payload[summary_start + half .. summary_start + summary_len],
                    .chunk_errors = self.error_payload[error_start .. error_start + error_len],
                    .scratch = self.scratch_payload[scratch_start .. scratch_start + scratch_len],
                };
                try storage.validate();
            }
            if (shared.summary > shape.summary_cells or
                shared.errors > shape.error_slots or shared.scratch > shape.scratch_cells)
            {
                return error.InvalidTree2ProductionResources;
            }
        }

        fn prepareMemoryStarts(self: *State) !void {
            var row_start: usize = 0;
            for (self.statement.infra_descs[0..self.statement.n_infra], 0..) |desc, infra_index| {
                self.memory_row_starts[infra_index] = row_start;
                if (desc.kind == .memory) row_start = try checkedAdd(row_start, desc.n_rows);
            }
            const expected = self.inputs.witness.memoryBoundaryRows().len;
            if (row_start != expected) return error.InvalidTree2ProductionInput;
        }

        pub fn run(
            raw_context: *anyopaque,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) anyerror!void {
            const self: *State = @ptrCast(@alignCast(raw_context));
            if (context.isCancelled()) return;
            switch (task.kind) {
                .reserve => try self.reserve(task),
                .seal => try self.seal(task),
                else => try self.produce(task, context),
            }
        }

        pub fn runProfiled(
            raw_context: *anyopaque,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) anyerror!void {
            const self: *State = @ptrCast(@alignCast(raw_context));
            if (context.isCancelled()) return;
            switch (task.kind) {
                .reserve => try self.reserve(task),
                .seal => try self.sealProfiled(task),
                else => {
                    try self.produce(task, context);
                    if (context.isCancelled()) return;
                    const registry_index: usize = @intCast(task.registry_index orelse
                        return error.InvalidTree2ProductionTask);
                    if (registry_index >= self.plan.descriptor_count or
                        self.ownership[registry_index].load(.acquire) != 1)
                    {
                        return error.IncompleteTree2ProductionOwner;
                    }
                    try self.recordDescriptorWork(task, registry_index);
                },
            }
        }

        fn reserve(self: *State, task: *const execution.Task) !void {
            if (task.columns != null or task.claims != null or task.registry_index != null) {
                return error.InvalidTree2ProductionTask;
            }
            if (self.reserved.swap(true, .acq_rel)) {
                return error.DuplicateTree2ProductionReserve;
            }
            for (self.ownership) |*slot| {
                if (slot.load(.acquire) != 0) return error.Tree2ProductionOwnerNotPristine;
            }
        }

        fn seal(self: *State, task: *const execution.Task) !void {
            if (task.columns != null or task.claims != null or task.registry_index != null or
                !self.reserved.load(.acquire))
            {
                return error.InvalidTree2ProductionTask;
            }
            for (self.ownership) |*slot| {
                if (slot.load(.acquire) != 1) return error.IncompleteTree2ProductionOwner;
            }
            if (self.sealed.swap(true, .acq_rel)) {
                return error.DuplicateTree2ProductionSeal;
            }
        }

        fn sealProfiled(self: *State, task: *const execution.Task) !void {
            const work = self.work orelse return error.InteractionWorkReceiptUnavailable;
            var completed = work.completed;
            for (work.descriptor_receipts) |receipt| {
                try completed.observe(
                    &work.authority,
                    .base,
                    work.session_digest,
                    receipt orelse return error.IncompleteInteractionWorkReceipt,
                );
            }
            const receipt = try interaction_witness_work.seal(
                &work.authority,
                .base,
                work.session_digest,
                completed,
            );
            try self.seal(task);
            work.completed = completed;
            work.receipt = receipt;
        }

        fn recordDescriptorWork(
            self: *State,
            task: *const execution.Task,
            registry_index: usize,
        ) !void {
            const work = self.work orelse return error.InteractionWorkReceiptUnavailable;
            if (work.descriptor_receipts[registry_index] != null)
                return error.DuplicateInteractionWorkProducer;
            const counts = try self.descriptorWorkCounts(task, registry_index);
            work.descriptor_receipts[registry_index] =
                try interaction_witness_work.completeInteraction(
                    &work.authority,
                    .base_interaction_trace,
                    .base,
                    work.session_digest,
                    counts,
                );
        }

        fn descriptorWorkCounts(
            self: *const State,
            task: *const execution.Task,
            registry_index: usize,
        ) !interaction_witness_work.Counts {
            const storage = &self.storages[registry_index];
            var counts = interaction_witness_work.Counts{};
            const relation_shape = try descriptorRelationShape(task);
            try interaction_witness_work.observeRelationRows(
                &counts,
                relation_shape.rows,
                relation_shape.combinations_per_row,
                relation_shape.inputs_per_row,
            );

            const terms = try checkedMul(storage.trace_size, storage.n_sums);
            try interaction_witness_work.observeLogupTerms(
                &counts,
                terms,
                terms,
                0,
            );
            for (0..storage.chunkCount()) |chunk_index| {
                const row_start = chunk_index * prepared_logup.CHUNK_ROWS;
                const chunk_len = @min(
                    storage.trace_size - row_start,
                    prepared_logup.CHUNK_ROWS,
                );
                try interaction_witness_work.observeBatchInverse(
                    &counts,
                    try checkedMul(storage.n_sums, chunk_len),
                );
                counts.chunk_scan_additions = try checkedAddU64(
                    counts.chunk_scan_additions,
                    @intCast(storage.n_sums),
                );
                for (0..storage.n_sums) |sum_index| {
                    const offset = storage.chunk_offsets[
                        chunk_index * storage.n_sums + sum_index
                    ];
                    if (!offset.isZero()) {
                        counts.offset_additions = try checkedAddU64(
                            counts.offset_additions,
                            @intCast(chunk_len),
                        );
                    }
                }
            }
            return counts;
        }

        const RelationShape = struct {
            rows: usize,
            combinations_per_row: usize,
            inputs_per_row: usize,
        };

        fn descriptorRelationShape(
            task: *const execution.Task,
        ) !RelationShape {
            return switch (task.kind) {
                .opcode => blk: {
                    const family = task.opcode_family orelse
                        return error.InvalidTree2ProductionTask;
                    var zeros = [_]BaseScalar{BaseScalar.zero()} **
                        trace_mod.MAX_FAMILY_COLUMNS;
                    const list = try OpcodeBaseEntries.fromMain(
                        family,
                        zeros[0..trace_mod.nColumnsForFamily(family)],
                    );
                    var inputs: usize = 0;
                    for (list.entries[0..list.len]) |entry| {
                        inputs = try checkedAdd(inputs, entry.arity);
                    }
                    break :blk .{
                        .rows = try domainSize(task.log_size),
                        .combinations_per_row = list.len,
                        .inputs_per_row = inputs,
                    };
                },
                .program => .{ .rows = task.n_rows, .combinations_per_row = 7, .inputs_per_row = 24 },
                .memory => .{ .rows = task.n_rows, .combinations_per_row = 7, .inputs_per_row = 27 },
                .merkle => .{ .rows = task.n_rows, .combinations_per_row = 5, .inputs_per_row = 44 },
                .poseidon2 => .{ .rows = task.n_rows, .combinations_per_row = 4, .inputs_per_row = 80 },
                .clock_update => .{
                    .rows = try domainSize(task.log_size),
                    .combinations_per_row = 4,
                    .inputs_per_row = 17,
                },
                .lookup_table => blk: {
                    const kind = statement_mod.tableKind(task.infra_kind orelse
                        return error.InvalidTree2ProductionTask) orelse
                        return error.InvalidTree2ProductionTask;
                    break :blk .{
                        .rows = try domainSize(task.log_size),
                        .combinations_per_row = 1,
                        .inputs_per_row = lookup_schema.arity(kind),
                    };
                },
                .reserve, .seal => return error.InvalidTree2ProductionTask,
            };
        }

        fn produce(
            self: *State,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) !void {
            if (!self.reserved.load(.acquire)) return error.Tree2ProductionReserveBarrier;
            const registry_index: usize = @intCast(task.registry_index orelse
                return error.InvalidTree2ProductionTask);
            if (registry_index >= self.plan.descriptor_count) {
                return error.InvalidTree2ProductionTask;
            }
            const column_range = self.plan.descriptorColumnRange(registry_index) orelse
                return error.InvalidTree2ProductionTask;
            const claim_range = self.plan.descriptorClaimRange(registry_index) orelse
                return error.InvalidTree2ProductionTask;
            if (task.columns == null or task.claims == null or
                !std.meta.eql(task.columns.?, column_range) or
                !std.meta.eql(task.claims.?, claim_range) or
                task.class != self.plan.descriptorClass(registry_index).?)
            {
                return error.InvalidTree2ProductionTask;
            }
            try self.requireUnowned(registry_index, column_range, claim_range);

            var destinations: [MAX_COLUMNS_PER_DESCRIPTOR][]M31 = undefined;
            if (column_range.len > destinations.len) {
                return error.InvalidTree2ProductionDestination;
            }
            for (destinations[0..column_range.len], 0..) |*destination, index| {
                destination.* = @constCast(self.columns[column_range.start + index].values);
            }
            const storage = &self.storages[registry_index];
            const placement = self.placements[task.log_size] orelse
                return error.InvalidTree2ProductionPlacement;
            const completed = switch (task.kind) {
                .opcode => try self.produceOpcode(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .program => try self.produceProgram(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .memory => try self.produceMemory(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .merkle => try self.produceMerkle(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .poseidon2 => try self.producePoseidon(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .clock_update => try self.produceClock(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .lookup_table => try self.produceTable(
                    task,
                    storage,
                    placement,
                    destinations[0..column_range.len],
                    context,
                ),
                .reserve, .seal => return error.InvalidTree2ProductionTask,
            };
            if (!completed) return;
            try self.complete(registry_index, column_range, claim_range);
        }

        fn produceOpcode(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const component_index: usize = @intCast(task.component_index orelse
                return error.InvalidTree2ProductionTask);
            if (component_index >= self.statement.n_components or
                task.infra_index != null)
            {
                return error.InvalidTree2ProductionTask;
            }
            const desc = self.statement.component_descs[component_index];
            if (task.opcode_family == null or task.opcode_family.? != desc.family or
                task.infra_kind != null or task.log_size != desc.log_size or
                task.n_rows != desc.n_rows)
            {
                return error.InvalidTree2ProductionTask;
            }
            var main_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
            const views = try self.inputs.main_source.opcodeColumns(
                self.statement,
                component_index,
                &main_columns,
            );
            const row_context = OpcodeRows{
                .family = desc.family,
                .columns = views,
                .relations = self.inputs.relations,
                .n_sums = opcode_entries.batchCount(desc.family),
            };
            return prepared_logup.runInto(
                MAX_SUMS,
                storage,
                placement,
                row_context,
                row_context.n_sums,
                columns,
                self.inputs.claim.opcode_claims[component_index][0..row_context.n_sums],
                context,
            );
        }

        fn produceProgram(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const infra_index = try self.requireInfra(task, .program);
            return prepared_logup.runInto(
                program_interaction.N_SUMS,
                storage,
                placement,
                ProgramRows{
                    .rows = self.inputs.witness.program.rows,
                    .relations = self.inputs.relations,
                },
                program_interaction.N_SUMS,
                columns,
                &self.inputs.claim.program_claims[infra_index],
                context,
            );
        }

        fn produceMemory(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const infra_index = try self.requireInfra(task, .memory);
            const boundary_rows = self.inputs.witness.memoryBoundaryRows();
            if (boundary_rows.len == 0)
                return error.InvalidTree2ProductionInput;
            const start = self.memory_row_starts[infra_index];
            const rows = boundary_rows[start .. start + task.n_rows];
            return prepared_logup.runInto(
                memory_interaction.N_SUMS,
                storage,
                placement,
                MemoryRows{ .rows = rows, .relations = self.inputs.relations },
                memory_interaction.N_SUMS,
                columns,
                &self.inputs.claim.memory_claims[infra_index],
                context,
            );
        }

        fn produceMerkle(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const infra_index = try self.requireInfra(task, .merkle);
            return prepared_logup.runInto(
                merkle_node.N_SUMS,
                storage,
                placement,
                MerkleRows{
                    .rows = self.inputs.witness.merkleRows(),
                    .relations = self.inputs.relations,
                },
                merkle_node.N_SUMS,
                columns,
                &self.inputs.claim.merkle_claims[infra_index],
                context,
            );
        }

        fn producePoseidon(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const infra_index = try self.requireInfra(task, .poseidon2);
            return prepared_logup.runInto(
                poseidon2_air.N_SUMS,
                storage,
                placement,
                PoseidonRows{
                    .calls = self.inputs.witness.poseidonCalls(),
                    .relations = self.inputs.relations,
                },
                poseidon2_air.N_SUMS,
                columns,
                &self.inputs.claim.poseidon_claims[infra_index],
                context,
            );
        }

        fn produceClock(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const infra_index = try self.requireInfra(task, .clock_update);
            var main_columns: [clock_interaction.N_MAIN_COLUMNS][]const M31 = undefined;
            _ = try self.inputs.main_source.clockColumns(self.statement, &main_columns);
            return prepared_logup.runInto(
                clock_interaction.N_SUMS,
                storage,
                placement,
                ClockRows{
                    .columns = main_columns,
                    .relations = self.inputs.relations,
                },
                clock_interaction.N_SUMS,
                columns,
                &self.inputs.claim.clock_claims[infra_index],
                context,
            );
        }

        fn produceTable(
            self: *State,
            task: *const execution.Task,
            storage: *prepared_logup.Storage,
            placement: infra.BitReversalTable,
            columns: []const []M31,
            context: *task_graph.TaskContext,
        ) !bool {
            const infra_index: usize = @intCast(task.infra_index orelse
                return error.InvalidTree2ProductionTask);
            if (infra_index >= self.statement.n_infra) {
                return error.InvalidTree2ProductionTask;
            }
            const desc = self.statement.infra_descs[infra_index];
            const kind = statement_mod.tableKind(desc.kind) orelse
                return error.InvalidTree2ProductionTask;
            _ = try self.requireInfra(task, desc.kind);
            const counter = try self.inputs.main_source.lookupCounter(kind);
            return prepared_logup.runInto(
                1,
                storage,
                placement,
                TableRows{
                    .kind = kind,
                    .counter = counter,
                    .relations = self.inputs.relations,
                },
                1,
                columns,
                self.inputs.claim.lookup_claims[infra_index .. infra_index + 1],
                context,
            );
        }

        fn requireInfra(
            self: *const State,
            task: *const execution.Task,
            expected_kind: statement_mod.InfraKind,
        ) !usize {
            const infra_index: usize = @intCast(task.infra_index orelse
                return error.InvalidTree2ProductionTask);
            if (task.component_index != null or task.opcode_family != null or
                task.infra_kind == null or task.infra_kind.? != expected_kind or
                infra_index >= self.statement.n_infra)
            {
                return error.InvalidTree2ProductionTask;
            }
            const desc = self.statement.infra_descs[infra_index];
            if (desc.kind != expected_kind or task.log_size != desc.log_size or
                task.n_rows != desc.n_rows)
            {
                return error.InvalidTree2ProductionTask;
            }
            return infra_index;
        }

        fn requireUnowned(
            self: *State,
            registry_index: usize,
            columns: plan_mod.ColumnRange,
            claims: plan_mod.ClaimRange,
        ) !void {
            const column_base: usize = self.plan.descriptor_count;
            const claim_base = column_base + self.plan.total_columns;
            if (self.ownership[registry_index].load(.acquire) != 0) {
                return error.DuplicateTree2ProductionOwner;
            }
            for (self.ownership[column_base + columns.start ..][0..columns.len]) |*slot| {
                if (slot.load(.acquire) != 0) return error.DuplicateTree2ProductionOwner;
            }
            for (self.ownership[claim_base + claims.start ..][0..claims.len]) |*slot| {
                if (slot.load(.acquire) != 0) return error.DuplicateTree2ProductionOwner;
            }
        }

        fn complete(
            self: *State,
            registry_index: usize,
            columns: plan_mod.ColumnRange,
            claims: plan_mod.ClaimRange,
        ) !void {
            try self.requireUnowned(registry_index, columns, claims);
            const column_base: usize = self.plan.descriptor_count;
            const claim_base = column_base + self.plan.total_columns;
            for (self.ownership[column_base + columns.start ..][0..columns.len]) |*slot| {
                slot.store(1, .release);
            }
            for (self.ownership[claim_base + claims.start ..][0..claims.len]) |*slot| {
                slot.store(1, .release);
            }
            self.ownership[registry_index].store(1, .release);
        }
    };
}
