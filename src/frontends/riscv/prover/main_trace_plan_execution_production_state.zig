//! Production Tree-1 state machine and task callbacks.

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

pub fn makeState(comptime Owner: type) type {
    const Inputs = Owner.Inputs;
    const WorkState = Owner.WorkState;
    const PoseidonWorkState = Owner.PoseidonWorkState;
    const MAX_LOG_SIZES = Owner.MAX_LOG_SIZES;
    const MAX_COMPONENTS = Owner.MAX_COMPONENTS;
    const MAX_INFRA = Owner.MAX_INFRA;
    const expectedAdd = Owner.expectedAdd;

    return struct {
        const State = @This();

        allocator: std.mem.Allocator,
        plan: plan_mod.Plan,
        statement: *const statement_mod.RiscVStatement,
        inputs: Inputs,
        artifacts: *arena_mod.Artifacts,
        proof_opcodes: []trace_mod.ProofOpcode,
        chunk_counters: []lookup_counter.Set,
        initialized_counters: usize,
        poseidon_inverse: []usize,
        placements: [MAX_LOG_SIZES]?infra.BitReversalTable,
        component_placements: [MAX_COMPONENTS]infra.BitReversalTable,
        opcode_columns: [MAX_COMPONENTS][trace_mod.MAX_FAMILY_COLUMNS][]M31,
        retained_opcode: [MAX_COMPONENTS][trace_mod.MAX_FAMILY_COLUMNS][]M31,
        retained_clock: [infra.CLOCK_UPDATE_COLS][]M31,
        first_component: [trace_mod.N_FAMILIES]usize,
        family_component_counts: [trace_mod.N_FAMILIES]usize,
        chunk_family_offsets: [work_pool.MAX_WORKERS][trace_mod.N_FAMILIES]usize,
        memory_row_starts: [MAX_INFRA]usize,
        work: ?*WorkState,
        poseidon_work: ?*PoseidonWorkState,
        prepared: std.atomic.Value(bool) = .init(false),
        generation_done: std.atomic.Value(usize) = .init(0),
        reduced: std.atomic.Value(bool) = .init(false),
        audits_done: std.atomic.Value(usize) = .init(0),
        lookup_seeded: std.atomic.Value(bool) = .init(false),
        finalization_done: std.atomic.Value(usize) = .init(0),
        sealed: std.atomic.Value(bool) = .init(false),

        pub fn init(
            allocator: std.mem.Allocator,
            plan: *const plan_mod.Plan,
            statement: *const statement_mod.RiscVStatement,
            inputs: Inputs,
            destination_policy: arena_mod.DestinationPolicy,
        ) !*State {
            const self = try allocator.create(State);
            self.* = .{
                .allocator = allocator,
                .plan = plan.*,
                .statement = statement,
                .inputs = inputs,
                .artifacts = undefined,
                .proof_opcodes = &.{},
                .chunk_counters = &.{},
                .initialized_counters = 0,
                .poseidon_inverse = &.{},
                .placements = .{null} ** MAX_LOG_SIZES,
                .component_placements = undefined,
                .opcode_columns = undefined,
                .retained_opcode = undefined,
                .retained_clock = undefined,
                .first_component = .{std.math.maxInt(usize)} ** trace_mod.N_FAMILIES,
                .family_component_counts = .{0} ** trace_mod.N_FAMILIES,
                .chunk_family_offsets = .{.{0} ** trace_mod.N_FAMILIES} ** work_pool.MAX_WORKERS,
                .memory_row_starts = .{0} ** MAX_INFRA,
                .work = null,
                .poseidon_work = null,
            };
            var artifacts_initialized = false;
            errdefer {
                self.deinitPrepared(artifacts_initialized);
                allocator.destroy(self);
            }

            try self.validateInputs();
            if (inputs.capture_main_witness_work) {
                self.work = try WorkState.init(allocator);
            }
            if (inputs.witness.poseidonWorkShard()) |initial| {
                self.poseidon_work = try PoseidonWorkState.init(allocator, initial);
            }
            self.artifacts = try arena_mod.Artifacts.initWithPolicy(
                allocator,
                statement,
                plan,
                destination_policy,
            );
            artifacts_initialized = true;
            try self.preparePlacements();
            try self.bindDestinations();
            self.proof_opcodes = try inputs.execution_trace.proofOpcodes(allocator);
            try self.prepareOpcodeGeometry();
            try self.prepareCounters();
            try self.preparePoseidonInverse();
            return self;
        }

        pub fn deinit(self: *State) void {
            const allocator = self.allocator;
            self.deinitPrepared(true);
            allocator.destroy(self);
        }

        fn deinitPrepared(self: *State, artifacts_initialized: bool) void {
            if (self.work) |work| {
                work.deinit(self.allocator);
                self.work = null;
            }
            if (self.poseidon_work) |work| {
                work.deinit(self.allocator);
                self.poseidon_work = null;
            }
            for (self.chunk_counters[0..self.initialized_counters]) |*counters| {
                counters.deinit(self.allocator);
            }
            if (self.chunk_counters.len != 0) self.allocator.free(self.chunk_counters);
            if (self.proof_opcodes.len != 0) self.allocator.free(self.proof_opcodes);
            if (self.poseidon_inverse.len != 0) self.allocator.free(self.poseidon_inverse);
            for (&self.placements) |*maybe_table| {
                if (maybe_table.*) |table| table.deinit(self.allocator);
                maybe_table.* = null;
            }
            if (artifacts_initialized) self.artifacts.deinit();
        }

        fn validateInputs(self: *State) !void {
            const statement = self.statement;
            const witness = self.inputs.witness;
            const geometry = self.inputs.geometry;
            if (geometry.merkle_infra_index >= statement.n_infra or
                geometry.poseidon_infra_index >= statement.n_infra or
                geometry.clock_infra_index >= statement.n_infra)
            {
                return error.InvalidProductionInput;
            }
            if (self.inputs.execution_trace.rows.items.len != self.plan.ordinary_steps or
                witness.program.rows.len != statement.infra_descs[0].n_rows or
                geometry.program_log_size != statement.infra_descs[0].log_size or
                geometry.poseidon_infra_index != self.plan.poseidon_infra_index or
                geometry.poseidon_log_size !=
                    statement.infra_descs[geometry.poseidon_infra_index].log_size or
                witness.merkleRows().len !=
                    statement.infra_descs[geometry.merkle_infra_index].n_rows or
                witness.poseidonCalls().len !=
                    statement.infra_descs[geometry.poseidon_infra_index].n_rows)
            {
                return error.InvalidProductionInput;
            }
            const clock_rows = if (self.inputs.state_chain) |chain|
                chain.clock_updates_reg.items.len + chain.clock_updates_mem.items.len
            else
                0;
            if (clock_rows != statement.infra_descs[geometry.clock_infra_index].n_rows) {
                return error.InvalidProductionInput;
            }
            const boundary_rows = witness.memoryBoundaryRows().len;
            var described_rows: usize = 0;
            var infra_index: usize = 1;
            while (infra_index < statement.n_infra and
                statement.infra_descs[infra_index].kind == .memory)
            {
                self.memory_row_starts[infra_index] = described_rows;
                described_rows += statement.infra_descs[infra_index].n_rows;
                infra_index += 1;
            }
            if (described_rows != boundary_rows or
                infra_index != geometry.merkle_infra_index or
                geometry.poseidon_infra_index != infra_index + 1 or
                geometry.clock_infra_index != infra_index + 2)
            {
                return error.InvalidProductionInput;
            }
        }

        fn preparePlacements(self: *State) !void {
            for (self.statement.component_descs[0..self.statement.n_components]) |desc| {
                try self.ensurePlacement(desc.log_size);
            }
            for (self.statement.infra_descs[0..self.statement.n_infra]) |desc| {
                try self.ensurePlacement(desc.log_size);
            }
        }

        fn ensurePlacement(self: *State, log_size: u32) !void {
            const index: usize = @intCast(log_size);
            if (index >= self.placements.len) return error.InvalidProductionInput;
            if (self.placements[index] == null) {
                self.placements[index] = try infra.BitReversalTable.init(
                    self.allocator,
                    log_size,
                );
            }
        }

        fn bindDestinations(self: *State) !void {
            var retained_cursor: usize = 0;
            for (0..self.statement.n_components) |component_index| {
                const desc = self.statement.component_descs[component_index];
                const range = self.plan.componentRange(component_index) orelse
                    return error.InvalidProductionDestinationShape;
                self.component_placements[component_index] =
                    self.placements[desc.log_size].?;
                for (0..desc.n_columns) |column_index| {
                    self.opcode_columns[component_index][column_index] =
                        try self.artifacts.mutableColumn(range.start + column_index);
                    const len = self.opcode_columns[component_index][column_index].len;
                    if (retained_cursor > self.artifacts.retained_payload.len or
                        len > self.artifacts.retained_payload.len - retained_cursor)
                    {
                        return error.InvalidProductionDestinationShape;
                    }
                    self.retained_opcode[component_index][column_index] =
                        self.artifacts.retained_payload[retained_cursor .. retained_cursor + len];
                    retained_cursor += len;
                }
            }
            const clock_range = self.plan.infrastructureRange(
                self.inputs.geometry.clock_infra_index,
            ) orelse return error.InvalidProductionDestinationShape;
            for (&self.retained_clock, 0..) |*column, index| {
                const main = try self.artifacts.mutableColumn(clock_range.start + index);
                if (retained_cursor > self.artifacts.retained_payload.len or
                    main.len > self.artifacts.retained_payload.len - retained_cursor)
                {
                    return error.InvalidProductionDestinationShape;
                }
                column.* = self.artifacts.retained_payload[retained_cursor .. retained_cursor + main.len];
                retained_cursor += main.len;
            }
            if (retained_cursor != self.artifacts.retained_payload.len) {
                return error.InvalidProductionDestinationShape;
            }
        }

        fn prepareOpcodeGeometry(self: *State) !void {
            for (0..self.statement.n_components) |component_index| {
                const family = self.statement.component_descs[component_index].family;
                const family_index = @intFromEnum(family);
                if (self.family_component_counts[family_index] == 0) {
                    self.first_component[family_index] = component_index;
                }
                self.family_component_counts[family_index] += 1;
            }
            var counts = [_]usize{0} ** trace_mod.N_FAMILIES;
            for (self.plan.opcodeChunks(), 0..) |rows, chunk_index| {
                self.chunk_family_offsets[chunk_index] = counts;
                const start: usize = @intCast(rows.start);
                const end: usize = @intCast(try rows.end());
                for (self.proof_opcodes[start..end]) |proof_opcode| {
                    counts[@intFromEnum(trace_mod.opcodeFamily(proof_opcode))] += 1;
                }
            }
            for (0..trace_mod.N_FAMILIES) |family_index| {
                var described: usize = 0;
                if (self.family_component_counts[family_index] != 0) {
                    const first = self.first_component[family_index];
                    for (0..self.family_component_counts[family_index]) |shard| {
                        described += self.statement.component_descs[first + shard].n_rows;
                    }
                }
                if (described != counts[family_index]) return error.InvalidProductionInput;
            }
        }

        fn prepareCounters(self: *State) !void {
            self.chunk_counters = try self.allocator.alloc(
                lookup_counter.Set,
                self.plan.opcode_chunk_count,
            );
            for (self.chunk_counters) |*counters| {
                counters.* = try lookup_counter.Set.init(self.allocator);
                self.initialized_counters += 1;
            }
        }

        fn preparePoseidonInverse(self: *State) !void {
            const desc = self.statement.infra_descs[self.plan.poseidon_infra_index];
            const placement = self.placements[desc.log_size].?;
            self.poseidon_inverse = try self.allocator.alloc(
                usize,
                placement.mapping.len,
            );
            for (placement.mapping, 0..) |committed_row, logical_row| {
                self.poseidon_inverse[committed_row] = logical_row;
            }
        }

        pub fn run(
            opaque_context: *anyopaque,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) anyerror!void {
            const self: *State = @ptrCast(@alignCast(opaque_context));
            if (context.isCancelled()) return;
            switch (task.kind) {
                .prepare => {
                    if (self.prepared.swap(true, .acq_rel)) {
                        return error.DuplicateProductionPrepare;
                    }
                },
                .opcode_fill => if (try self.fillOpcode(task, context)) {
                    _ = self.generation_done.fetchAdd(1, .release);
                },
                .infrastructure_fill => if (try self.fillInfrastructure(task, context)) {
                    _ = self.generation_done.fetchAdd(1, .release);
                },
                .poseidon_fill => if (try self.fillPoseidon(task, context)) {
                    _ = self.generation_done.fetchAdd(1, .release);
                },
                .opcode_reduce => try self.reduce(),
                .opcode_audit => if (try self.audit(task, context)) {
                    _ = self.audits_done.fetchAdd(1, .release);
                },
                .lookup_seed => try self.seedLookups(context),
                .opcode_finalize => try self.finalizeOpcode(task),
                .lookup_finalize => try self.finalizeLookup(task, context),
                .seal => try self.seal(),
            }
        }

        fn requirePrepared(self: *State) !void {
            if (!self.prepared.load(.acquire)) return error.ProductionPrepareBarrier;
        }

        fn fillOpcode(
            self: *State,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) !bool {
            try self.requirePrepared();
            const rows = task.rows orelse return error.InvalidProductionTask;
            const start: usize = @intCast(rows.start);
            const end: usize = @intCast(try rows.end());
            const chunk_index: usize = @intCast(task.chunk_index);
            if (chunk_index >= self.chunk_counters.len or
                end > self.inputs.execution_trace.rows.items.len or
                task.registry_index != null or
                task.columns != null or
                !std.meta.eql(rows, self.plan.opcodeChunks()[chunk_index]))
            {
                return error.InvalidProductionTask;
            }
            if (self.work) |work| {
                return generators.fillOpcodeChunkProfiled(
                    &self.opcode_columns,
                    &self.component_placements,
                    &self.first_component,
                    &self.family_component_counts,
                    self.chunk_family_offsets[chunk_index],
                    self.inputs.execution_trace.rows.items[start..end],
                    self.proof_opcodes[start..end],
                    &self.chunk_counters[chunk_index],
                    &work.authority,
                    &work.opcode[chunk_index],
                    context,
                );
            }
            return generators.fillOpcodeChunk(
                &self.opcode_columns,
                &self.component_placements,
                &self.first_component,
                &self.family_component_counts,
                self.chunk_family_offsets[chunk_index],
                self.inputs.execution_trace.rows.items[start..end],
                self.proof_opcodes[start..end],
                &self.chunk_counters[chunk_index],
                context,
            );
        }

        fn fillInfrastructure(
            self: *State,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) !bool {
            try self.requirePrepared();
            const registry: usize = @intCast(task.registry_index orelse
                return error.InvalidProductionTask);
            if (registry < self.statement.n_components) return error.InvalidProductionTask;
            const infra_index = registry - self.statement.n_components;
            if (infra_index >= self.statement.n_infra) return error.InvalidProductionTask;
            const desc = self.statement.infra_descs[infra_index];
            const range = self.plan.infrastructureRange(infra_index) orelse
                return error.InvalidProductionTask;
            if (task.columns == null or
                !std.meta.eql(task.columns.?, range) or
                task.rows != null or
                task.chunk_index != 0)
            {
                return error.InvalidProductionTask;
            }
            const placement = self.placements[desc.log_size].?;
            const work_shard: ?*main_witness_work.Shard = if (self.work) |work|
                &work.infrastructure[infra_index]
            else
                null;
            const completed = switch (desc.kind) {
                .program => program: {
                    var destinations = try self.columns(
                        program_commitment.N_MAIN_COLUMNS,
                        range,
                    );
                    break :program try generators.fillProgram(
                        &destinations,
                        self.inputs.witness.program.rows,
                        placement,
                        work_shard,
                        context,
                    );
                },
                .memory => memory: {
                    const boundary_rows = self.inputs.witness.memoryBoundaryRows();
                    if (boundary_rows.len == 0)
                        return error.InvalidProductionInput;
                    const start = self.memory_row_starts[infra_index];
                    var destinations = try self.columns(8, range);
                    break :memory try generators.fillMemory(
                        &destinations,
                        boundary_rows[start .. start + desc.n_rows],
                        placement,
                        work_shard,
                        context,
                    );
                },
                .merkle => merkle: {
                    var destinations = try self.columns(merkle_node.N_MAIN_COLUMNS, range);
                    break :merkle try generators.fillMerkle(
                        &destinations,
                        self.inputs.witness.merkleRows(),
                        placement,
                        work_shard,
                        context,
                    );
                },
                .clock_update => clock: {
                    var destinations = try self.columns(infra.CLOCK_UPDATE_COLS, range);
                    break :clock try generators.fillClock(
                        &destinations,
                        &self.retained_clock,
                        self.inputs.state_chain,
                        placement,
                        desc.n_rows,
                        work_shard,
                        context,
                    );
                },
                else => return error.InvalidProductionTask,
            };
            if (completed) try self.artifacts.completeRange(range);
            return completed;
        }

        fn fillPoseidon(
            self: *State,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) !bool {
            try self.requirePrepared();
            const range = self.plan.infrastructureRange(self.plan.poseidon_infra_index) orelse
                return error.InvalidProductionTask;
            const chunk_index: usize = @intCast(task.chunk_index);
            if (chunk_index >= self.plan.poseidonChunks().len or
                task.registry_index !=
                    self.statement.n_components + self.plan.poseidon_infra_index or
                task.columns == null or
                !std.meta.eql(task.columns.?, range) or
                task.rows == null or
                !std.meta.eql(task.rows.?, self.plan.poseidonChunks()[chunk_index]))
            {
                return error.InvalidProductionTask;
            }
            var destinations = try self.columns(poseidon2_air.N_MAIN_COLUMNS, range);
            if (self.poseidon_work) |work| {
                if (work.chunks[chunk_index] != null)
                    return error.DuplicatePoseidonWorkReceipt;
                const result = try generators.fillPoseidonRangeWithWorkReceipt(
                    &destinations,
                    self.inputs.witness.poseidonCalls(),
                    self.poseidon_inverse,
                    task.rows orelse return error.InvalidProductionTask,
                    &work.authority,
                    context,
                );
                if (result.completed) {
                    work.chunks[chunk_index] = result.receipt orelse
                        return error.PoseidonWorkReceiptNotCaptured;
                } else if (result.receipt != null) {
                    return error.InvalidPoseidonWorkReceipt;
                }
                return result.completed;
            }
            return generators.fillPoseidonRange(
                &destinations,
                self.inputs.witness.poseidonCalls(),
                self.poseidon_inverse,
                task.rows orelse return error.InvalidProductionTask,
                context,
            );
        }

        fn reduce(self: *State) !void {
            if (self.generation_done.load(.acquire) !=
                self.plan.task_counts.generation_wave)
            {
                return error.ProductionGenerationBarrier;
            }
            if (self.reduced.swap(true, .acq_rel)) return error.DuplicateProductionReduce;
            for (self.chunk_counters[1..self.initialized_counters]) |*source| {
                self.chunk_counters[0].mergeFrom(source);
                source.deinit(self.allocator);
            }
            if (self.work) |work| try work.reduction.observeCounterSetMerges(
                &work.authority,
                self.initialized_counters - 1,
            );
            // Only the canonical reduced set survives the reduction barrier. It is
            // retained for Tree 2; worker-private 11 MiB sets must not inflate the
            // proof-lifetime high-water mark after their last use.
            self.initialized_counters = 1;
            for (0..self.statement.n_components) |component_index| {
                try self.artifacts.completeRange(
                    self.plan.componentRange(component_index).?,
                );
            }
            try self.artifacts.completeRange(
                self.plan.infrastructureRange(self.plan.poseidon_infra_index).?,
            );
        }

        fn audit(
            self: *State,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) !bool {
            if (!self.reduced.load(.acquire)) return error.ProductionReduceBarrier;
            const component_index: usize = @intCast(task.registry_index orelse
                return error.InvalidProductionTask);
            if (component_index >= self.statement.n_components) {
                return error.InvalidProductionTask;
            }
            const desc = self.statement.component_descs[component_index];
            const range = self.plan.componentRange(component_index).?;
            if (task.rows != null or
                task.chunk_index != 0 or
                task.columns == null or
                !std.meta.eql(task.columns.?, range))
            {
                return error.InvalidProductionTask;
            }
            const work_authority: ?*const main_witness_work.Authority =
                if (self.work) |work| &work.authority else null;
            const work_shard: ?*main_witness_work.Shard =
                if (self.work) |work| &work.audit[component_index] else null;
            return generators.auditOpcode(
                &self.opcode_columns[component_index],
                desc.family,
                desc.n_columns,
                desc.n_rows,
                self.component_placements[component_index],
                work_authority,
                work_shard,
                context,
            );
        }

        fn seedLookups(
            self: *State,
            context: *task_graph.TaskContext,
        ) !void {
            if (!self.reduced.load(.acquire) or
                self.audits_done.load(.acquire) != self.plan.task_counts.audit_wave)
            {
                return error.ProductionAuditBarrier;
            }
            if (self.lookup_seeded.swap(true, .acq_rel)) {
                return error.DuplicateProductionLookupSeed;
            }
            errdefer self.lookup_seeded.store(false, .release);
            const memory_rows: []const memory_boundary.Row =
                self.inputs.witness.memoryBoundaryRows();
            const clock_range = self.plan.infrastructureRange(
                self.inputs.geometry.clock_infra_index,
            ).?;
            var clock_columns = try self.columns(
                infra.CLOCK_UPDATE_COLS,
                clock_range,
            );
            const work_authority: ?*const main_witness_work.Authority =
                if (self.work) |work| &work.authority else null;
            const work_shard: ?*main_witness_work.Shard =
                if (self.work) |work| &work.seed else null;
            const completed = try generators.seedLookups(
                &self.chunk_counters[0],
                self.inputs.witness.program.rows,
                memory_rows,
                &clock_columns,
                if (self.inputs.state_chain) |chain|
                    chain.clock_updates_reg.items.len +
                        chain.clock_updates_mem.items.len
                else
                    0,
                work_authority,
                work_shard,
                context,
            );
            if (!completed) {
                self.lookup_seeded.store(false, .release);
                return;
            }
            if (self.inputs.poseidon2_caller_lookup) |guest_lookup| {
                _ = try guest_lookup_registration.registerCallerColumns(
                    self.statement,
                    guest_lookup.extension,
                    &guest_lookup.columns,
                    guest_lookup.log_size,
                    guest_lookup.n_rows,
                    &self.chunk_counters[0],
                );
                if (self.work) |work| {
                    try work.seed.observeGuestLookupRows(
                        &work.authority,
                        guest_lookup.n_rows,
                    );
                }
            }
        }

        fn finalizeOpcode(self: *State, task: *const execution.Task) !void {
            if (!self.lookup_seeded.load(.acquire)) return error.ProductionLookupBarrier;
            const component_index: usize = @intCast(task.registry_index orelse
                return error.InvalidProductionTask);
            if (component_index >= self.statement.n_components) {
                return error.InvalidProductionTask;
            }
            const desc = self.statement.component_descs[component_index];
            const range = self.plan.componentRange(component_index).?;
            if (task.rows != null or
                task.chunk_index != 0 or
                task.columns == null or
                !std.meta.eql(task.columns.?, range))
            {
                return error.InvalidProductionTask;
            }
            if (!self.artifacts.rangeComplete(range)) return error.IncompleteProductionOwner;
            for (0..desc.n_columns) |column| {
                @memcpy(
                    self.retained_opcode[component_index][column],
                    self.opcode_columns[component_index][column],
                );
            }
            _ = self.finalization_done.fetchAdd(1, .release);
        }

        fn finalizeLookup(
            self: *State,
            task: *const execution.Task,
            context: *task_graph.TaskContext,
        ) !void {
            if (!self.lookup_seeded.load(.acquire)) return error.ProductionLookupBarrier;
            const registry: usize = @intCast(task.registry_index orelse
                return error.InvalidProductionTask);
            if (registry < self.statement.n_components) return error.InvalidProductionTask;
            const infra_index = registry - self.statement.n_components;
            if (infra_index >= self.statement.n_infra) return error.InvalidProductionTask;
            const desc = self.statement.infra_descs[infra_index];
            const kind = statement_mod.tableKind(desc.kind) orelse
                return error.InvalidProductionTask;
            const range = self.plan.infrastructureRange(infra_index).?;
            if (task.rows != null or
                task.chunk_index != 0 or
                task.columns == null or
                !std.meta.eql(task.columns.?, range))
            {
                return error.InvalidProductionTask;
            }
            const completed = try generators.fillLookup(
                try self.artifacts.mutableColumn(range.start),
                self.chunk_counters[0].get(kind),
                self.placements[lookup_schema.logSize(kind)].?,
                context,
            );
            if (!completed) return;
            try self.artifacts.completeRange(range);
            _ = self.finalization_done.fetchAdd(1, .release);
        }

        fn seal(self: *State) !void {
            if (self.finalization_done.load(.acquire) !=
                self.plan.task_counts.finalization_wave or
                !self.artifacts.allComplete())
            {
                return error.IncompleteProductionOwner;
            }
            if (self.work) |work| {
                var completed = main_witness_work.Shard{};
                for (work.opcode[0..self.plan.opcode_chunk_count]) |shard|
                    try completed.merge(shard);
                for (work.infrastructure[0..self.statement.n_infra]) |shard|
                    try completed.merge(shard);
                for (work.audit[0..self.statement.n_components]) |shard|
                    try completed.merge(shard);
                try completed.merge(work.reduction);
                try completed.merge(work.seed);
                try self.validateMainWitnessWorkShape(completed);
                work.receipt = try main_witness_work.seal(
                    &work.authority,
                    completed,
                );
            }
            if (self.poseidon_work) |work| {
                var completed = work.initial;
                for (work.chunks[0..self.plan.poseidonChunks().len]) |maybe_receipt| {
                    const receipt = maybe_receipt orelse
                        return error.PoseidonWorkReceiptNotCaptured;
                    try completed.observe(&work.authority, receipt);
                }
                if (completed.counts.base_air_rows !=
                    @as(u64, @intCast(self.inputs.witness.poseidonCalls().len)))
                {
                    return error.InvalidPoseidonWorkReceipt;
                }
                work.receipt = try poseidon_witness_work.seal(
                    &work.authority,
                    completed,
                );
            }
            if (self.sealed.swap(true, .acq_rel)) return error.DuplicateProductionSeal;
        }

        fn validateMainWitnessWorkShape(
            self: *const State,
            completed: main_witness_work.Shard,
        ) !void {
            var opcode_rows = [_]u64{0} ** trace_mod.N_FAMILIES;
            var audit_rows = [_]u64{0} ** trace_mod.N_FAMILIES;
            var program_rows: u64 = 0;
            var memory_rows: u64 = 0;
            var merkle_rows: u64 = 0;
            var clock_rows: u64 = 0;

            for (self.statement.component_descs[0..self.statement.n_components]) |desc| {
                const family_index = @intFromEnum(desc.family);
                opcode_rows[family_index] = std.math.add(
                    u64,
                    opcode_rows[family_index],
                    desc.n_rows,
                ) catch return error.MainWitnessWorkOverflow;
                if (self.plan.task_counts.audit_wave != 0) {
                    if (desc.log_size >= @bitSizeOf(u64))
                        return error.InvalidMainWitnessWorkShape;
                    audit_rows[family_index] = std.math.add(
                        u64,
                        audit_rows[family_index],
                        @as(u64, 1) << @intCast(desc.log_size),
                    ) catch return error.MainWitnessWorkOverflow;
                }
            }
            for (self.statement.infra_descs[0..self.statement.n_infra]) |desc| {
                switch (desc.kind) {
                    .program => program_rows = try expectedAdd(program_rows, desc.n_rows),
                    .memory => memory_rows = try expectedAdd(memory_rows, desc.n_rows),
                    .merkle => merkle_rows = try expectedAdd(merkle_rows, desc.n_rows),
                    .clock_update => clock_rows = try expectedAdd(clock_rows, desc.n_rows),
                    else => {},
                }
            }
            const clock_desc = self.statement.infra_descs[
                self.inputs.geometry.clock_infra_index
            ];
            if (clock_desc.log_size >= @bitSizeOf(u64))
                return error.InvalidMainWitnessWorkShape;
            const expected_merges = if (self.plan.opcode_chunk_count == 0)
                0
            else
                self.plan.opcode_chunk_count - 1;
            const expected_guest_lookup_rows: u64 =
                if (self.inputs.poseidon2_caller_lookup) |guest_lookup|
                    guest_lookup.n_rows
                else
                    0;
            if (!std.meta.eql(opcode_rows, completed.opcode_rows) or
                !std.meta.eql(audit_rows, completed.audit_rows) or
                completed.program_rows != program_rows or
                completed.memory_rows != memory_rows or
                completed.merkle_rows != merkle_rows or
                completed.clock_rows != clock_rows or
                completed.program_seed_rows != program_rows or
                completed.memory_seed_rows != memory_rows or
                completed.clock_seed_domain_rows !=
                    (@as(u64, 1) << @intCast(clock_desc.log_size)) or
                completed.clock_seed_active_rows != clock_rows or
                completed.guest_caller_trace_rows != 0 or
                completed.guest_lookup_rows != expected_guest_lookup_rows or
                completed.counter_set_merges != expected_merges)
            {
                return error.InvalidMainWitnessWorkShape;
            }
        }

        fn columns(
            self: *State,
            comptime count: usize,
            range: plan_mod.ColumnRange,
        ) ![count][]M31 {
            if (range.len != count) return error.InvalidProductionDestinationShape;
            var result: [count][]M31 = undefined;
            for (&result, 0..) |*column, index| {
                column.* = try self.artifacts.mutableColumn(range.start + index);
            }
            return result;
        }
    };
}
