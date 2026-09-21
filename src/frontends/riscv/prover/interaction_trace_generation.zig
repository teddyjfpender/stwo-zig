//! Interaction-column generators and exact-work accounting.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const work_pool = @import("stwo_prover_engine").work_pool;
const stage_profile = @import("stwo_prover_api").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");
const tree2_main_source = @import("tree2_main_source.zig");
const types = @import("types.zig");
const native_provider_omit = @import("memory_provider_shards/native_provider_omit_v1.zig");

const M31 = m31.M31;
const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const Relations = relation_challenges.Relations;
const RiscVInteractionClaim = types.RiscVInteractionClaim;

/// Selects the worker authority for base Tree-2 materialization. Profiled
/// sequential work must not inherit an ambient proof pool merely because later
/// proof stages are allowed to use it.
pub const BaseExecutionPolicy = enum {
    ambient,
    sequential,

    pub fn selectedPool(self: BaseExecutionPolicy) ?*work_pool.WorkPool {
        return switch (self) {
            .ambient => work_pool.getGlobalPool(),
            .sequential => null,
        };
    }

    pub fn requireSequentialReceipt(self: BaseExecutionPolicy) !void {
        if (self != .sequential)
            return error.UnsupportedProfiledInteractionExecution;
    }
};

pub fn Ops(comptime Owner: type) type {
    const LookupV2Admission = Owner.LookupV2Admission;

    return struct {
        pub fn generateBase(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            recorder: ?*stage_profile.Recorder,
            witness: *const CommitmentWitness,
            geometry: Geometry,
            main_source: *const tree2_main_source.Source,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            lookup_v2: ?LookupV2Admission,
            execution_policy: BaseExecutionPolicy,
        ) !void {
            return generateBaseForBackend(void, allocator, workspace, columns, recorder, witness, geometry, main_source, relations, claim, lookup_v2, execution_policy);
        }

        pub fn generateBaseForBackend(
            comptime Backend: type,
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            recorder: ?*stage_profile.Recorder,
            witness: *const CommitmentWitness,
            geometry: Geometry,
            main_source: *const tree2_main_source.Source,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            lookup_v2: ?LookupV2Admission,
            execution_policy: BaseExecutionPolicy,
        ) !void {
            const execution_pool = execution_policy.selectedPool();
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_opcode", "RISC-V opcode interactions");
                defer sub.end();
                if (lookup_v2) |authenticated| {
                    try generateOpcodeAuthenticatedLookupV2(
                        allocator,
                        workspace,
                        main_source,
                        columns,
                        relations,
                        claim,
                        authenticated.manifest,
                    );
                } else {
                    try generateOpcode(
                        allocator,
                        workspace,
                        main_source,
                        columns,
                        relations,
                        claim,
                        execution_pool,
                    );
                }
            }
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_program", "RISC-V program interactions");
                defer sub.end();
                try generateProgram(allocator, columns, witness, geometry, relations, claim);
            }
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_memory", "RISC-V memory interactions");
                defer sub.end();
                try generateMemory(allocator, workspace, columns, witness, relations, claim);
            }
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_merkle", "RISC-V Merkle interactions");
                defer sub.end();
                try generateMerkle(allocator, columns, witness, geometry, relations, claim, execution_pool);
            }
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_poseidon", "RISC-V Poseidon interactions");
                defer sub.end();
                try generatePoseidon(allocator, columns, witness, geometry, relations, claim, execution_pool);
            }
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_clock", "RISC-V clock interactions");
                defer sub.end();
                try generateClock(
                    allocator,
                    workspace,
                    main_source,
                    columns,
                    geometry,
                    relations,
                    claim,
                );
            }
            {
                var sub = try stage_profile.StageScope.begin(recorder, "riscv_interaction_tables", "RISC-V lookup-table interactions");
                defer sub.end();
                try generateLookupTables(
                    Backend,
                    allocator,
                    workspace,
                    columns,
                    main_source,
                    relations,
                    claim,
                    execution_pool,
                );
            }
        }

        /// Generates the authenticated V2 base prefix without the native
        /// narrow-memory Poseidon provider. The omission-aware geometry cannot
        /// name that provider; every retained component stays in declaration
        /// order and writes claims at its projected infrastructure index.
        pub fn generateBaseWithoutNativePoseidonAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            recorder: ?*stage_profile.Recorder,
            witness: *const CommitmentWitness,
            geometry: native_provider_omit.ProjectedGeometryV1,
            main_source: *const tree2_main_source.Source,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            manifest: *const lookup_physical_v2.Manifest,
            execution_policy: BaseExecutionPolicy,
        ) !void {
            const execution_pool = execution_policy.selectedPool();
            const projected = projectedLegacyGeometry(geometry);
            {
                var sub = try stage_profile.StageScope.begin(
                    recorder,
                    "riscv_interaction_opcode",
                    "RISC-V opcode interactions",
                );
                defer sub.end();
                try generateOpcodeAuthenticatedLookupV2(
                    allocator,
                    workspace,
                    main_source,
                    columns,
                    relations,
                    claim,
                    manifest,
                );
            }
            {
                var sub = try stage_profile.StageScope.begin(
                    recorder,
                    "riscv_interaction_program",
                    "RISC-V program interactions",
                );
                defer sub.end();
                try generateProgram(
                    allocator,
                    columns,
                    witness,
                    projected,
                    relations,
                    claim,
                );
            }
            {
                var sub = try stage_profile.StageScope.begin(
                    recorder,
                    "riscv_interaction_memory",
                    "RISC-V memory interactions",
                );
                defer sub.end();
                try generateMemory(allocator, workspace, columns, witness, relations, claim);
            }
            {
                var sub = try stage_profile.StageScope.begin(
                    recorder,
                    "riscv_interaction_merkle",
                    "RISC-V Merkle interactions",
                );
                defer sub.end();
                try generateMerkle(
                    allocator,
                    columns,
                    witness,
                    projected,
                    relations,
                    claim,
                    execution_pool,
                );
            }
            {
                var sub = try stage_profile.StageScope.begin(
                    recorder,
                    "riscv_interaction_clock",
                    "RISC-V clock interactions",
                );
                defer sub.end();
                try generateClock(
                    allocator,
                    workspace,
                    main_source,
                    columns,
                    projected,
                    relations,
                    claim,
                );
            }
            {
                var sub = try stage_profile.StageScope.begin(
                    recorder,
                    "riscv_interaction_tables",
                    "RISC-V lookup-table interactions",
                );
                defer sub.end();
                try generateLookupTables(
                    void,
                    allocator,
                    workspace,
                    columns,
                    main_source,
                    relations,
                    claim,
                    execution_pool,
                );
            }
        }

        fn generateOpcodeAuthenticatedLookupV2(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            main_source: *const tree2_main_source.Source,
            columns: *Columns,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            manifest: *const lookup_physical_v2.Manifest,
        ) !void {
            const statement = &workspace.statement;
            var opcode_main_offset: usize = 0;
            for (statement.component_descs[0..statement.n_components], 0..) |
                descriptor,
                index,
            | {
                const physical = manifest.entryForFamily(descriptor.family);
                try lookup_physical_v2.validatePinnedEntry(physical);
                const n_family_columns: usize = @intCast(descriptor.n_columns);
                var family_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
                _ = try main_source.opcodeColumns(statement, index, &family_columns);
                var generated = try opcode_interaction.generateSelectedRangesV2(
                    allocator,
                    descriptor.family,
                    physical.lookup_authority.entry_count,
                    physical.activeBatches(),
                    family_columns[0..n_family_columns],
                    descriptor.log_size,
                    relations,
                );
                @memcpy(
                    claim.opcode_claims[index][0..generated.n_batches],
                    generated.claims[0..generated.n_batches],
                );
                const n_columns = generated.nColumns();
                const taken = generated.takeColumns();
                for (taken[0..n_columns]) |values|
                    columns.append(descriptor.log_size, values);
                opcode_main_offset += n_family_columns;
            }
            std.debug.assert(opcode_main_offset == statement.nOpcodeMainColumns());
        }

        /// One opcode shard's interactions, from the exact buffers Tree 1 committed.
        ///
        /// The generated columns move into the Tree-2 owner below; the fixed-size claim
        /// is copied into its canonical registry slot before the temporary is consumed.
        fn generateOpcode(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            main_source: *const tree2_main_source.Source,
            columns: *Columns,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            execution_pool: ?*work_pool.WorkPool,
        ) !void {
            const statement = &workspace.statement;
            if (statement.n_components > 1) {
                if (execution_pool) |pool| {
                    return generateOpcodeParallel(
                        allocator,
                        workspace,
                        main_source,
                        columns,
                        relations,
                        claim,
                        pool,
                    );
                }
            }
            var opcode_main_offset: usize = 0;
            for (0..statement.n_components) |i| {
                const desc = statement.component_descs[i];
                const n_family_columns: usize = @intCast(desc.n_columns);
                var family_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
                _ = try main_source.opcodeColumns(statement, i, &family_columns);
                var generated = try opcode_interaction.generate(
                    allocator,
                    desc.family,
                    family_columns[0..n_family_columns],
                    desc.log_size,
                    relations,
                );
                @memcpy(
                    claim.opcode_claims[i][0..generated.n_batches],
                    generated.claims[0..generated.n_batches],
                );
                const n_columns = generated.nColumns();
                const taken = generated.takeColumns();
                for (taken[0..n_columns]) |values| columns.append(desc.log_size, values);
                opcode_main_offset += n_family_columns;
            }
            std.debug.assert(opcode_main_offset == statement.nOpcodeMainColumns());
        }

        /// Gives each large opcode family the whole bounded pool in turn. This avoids
        /// nested waits and lets the family generator parallelize its row-local tuple,
        /// inversion and scan work before results are appended in protocol order.
        fn generateOpcodeParallel(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            main_source: *const tree2_main_source.Source,
            columns: *Columns,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            pool: *work_pool.WorkPool,
        ) !void {
            const statement = &workspace.statement;
            var opcode_main_offset: usize = 0;
            var retained_plan: ?opcode_interaction.Plan = null;
            defer if (retained_plan) |*plan| plan.deinit();
            for (0..statement.n_components) |index| {
                const desc = statement.component_descs[index];
                const n_family_columns: usize = @intCast(desc.n_columns);
                var family_columns: [trace_mod.MAX_FAMILY_COLUMNS][]const M31 = undefined;
                _ = try main_source.opcodeColumns(statement, index, &family_columns);
                var generated = if (desc.log_size >= 12) blk: {
                    if (retained_plan == null or retained_plan.?.family != desc.family) {
                        if (retained_plan) |*plan| plan.deinit();
                        retained_plan = null;
                        retained_plan = try opcode_interaction.Plan.init(allocator, desc.family);
                    }
                    const plan = if (retained_plan) |*value| value else unreachable;
                    break :blk try opcode_interaction.generateParallelPlanned(
                        allocator,
                        plan,
                        family_columns[0..n_family_columns],
                        desc.log_size,
                        relations,
                        pool,
                    );
                } else try opcode_interaction.generate(
                    allocator,
                    desc.family,
                    family_columns[0..n_family_columns],
                    desc.log_size,
                    relations,
                );
                @memcpy(
                    claim.opcode_claims[index][0..generated.n_batches],
                    generated.claims[0..generated.n_batches],
                );
                const n_columns = generated.nColumns();
                const taken = generated.takeColumns();
                for (taken[0..n_columns]) |values| columns.append(desc.log_size, values);
                opcode_main_offset += @intCast(desc.n_columns);
            }
            std.debug.assert(opcode_main_offset == statement.nOpcodeMainColumns());
        }

        /// Program-table interactions. Program is infrastructure index 0 by
        /// construction, which is the index its claim is published under.
        fn generateProgram(
            allocator: std.mem.Allocator,
            columns: *Columns,
            witness: *const CommitmentWitness,
            geometry: Geometry,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
        ) !void {
            const generated = switch (witness.circuit_profile.programPolicy()) {
                .sparse_merkle_v1 => try program_interaction.generate(allocator, witness.program.rows, geometry.program_log_size, relations),
                .fixed_decoded_table_v1 => try program_interaction.generateWithPolicy(.fixed_decoded_table_v1, allocator, witness.program.rows, geometry.program_log_size, relations),
            };
            claim.program_claims[0] = generated.claims.sums;
            for (generated.columns) |values| columns.append(geometry.program_log_size, values);
        }

        /// RW-memory boundary interactions, over the shard partition Tree 1 committed.
        ///
        /// The rows are consumed by walking the declared shard descriptors rather than
        /// `memory_shard_lengths`, because each shard's claim is published under its
        /// infrastructure index; the running `row_start` and the final assertion are
        /// what tie the two views of the same partition together.
        fn generateMemory(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            witness: *const CommitmentWitness,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
        ) !void {
            const boundary_rows = witness.memoryBoundaryRows();
            if (boundary_rows.len == 0) return;
            const statement = &workspace.statement;
            var row_start: usize = 0;
            for (0..statement.n_infra) |infra_index| {
                const desc = statement.infra_descs[infra_index];
                if (desc.kind != .memory) continue;
                const row_end = row_start + desc.n_rows;
                const generated = try memory_interaction.generate(
                    allocator,
                    boundary_rows[row_start..row_end],
                    desc.log_size,
                    relations,
                );
                claim.memory_claims[infra_index] = generated.claims.sums;
                for (generated.columns) |values| columns.append(desc.log_size, values);
                row_start = row_end;
            }
            std.debug.assert(row_start == boundary_rows.len);
        }

        fn generateMerkle(
            allocator: std.mem.Allocator,
            columns: *Columns,
            witness: *const CommitmentWitness,
            geometry: Geometry,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            execution_pool: ?*work_pool.WorkPool,
        ) !void {
            const generated = if (geometry.merkle_log_size >= 12 and execution_pool != null)
                try merkle_node.generateInteractionParallel(
                    allocator,
                    witness.merkleRows(),
                    geometry.merkle_log_size,
                    relations,
                    execution_pool.?,
                )
            else
                try merkle_node.generateInteraction(
                    allocator,
                    witness.merkleRows(),
                    geometry.merkle_log_size,
                    relations,
                );
            claim.merkle_claims[geometry.merkle_infra_index] = generated.claims.sums;
            for (generated.columns) |values| columns.append(geometry.merkle_log_size, values);
        }

        fn generatePoseidon(
            allocator: std.mem.Allocator,
            columns: *Columns,
            witness: *const CommitmentWitness,
            geometry: Geometry,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            execution_pool: ?*work_pool.WorkPool,
        ) !void {
            const generated = if (geometry.poseidon_log_size >= 12 and execution_pool != null)
                try poseidon2_air.generateInteractionParallel(
                    allocator,
                    witness.poseidonCalls(),
                    geometry.poseidon_log_size,
                    relations,
                    execution_pool.?,
                )
            else
                try poseidon2_air.generateInteraction(
                    allocator,
                    witness.poseidonCalls(),
                    geometry.poseidon_log_size,
                    relations,
                );
            claim.poseidon_claims[geometry.poseidon_infra_index] = generated.claims.sums;
            for (generated.columns) |values| columns.append(geometry.poseidon_log_size, values);
        }

        /// Clock-update interactions read the workspace copy of the clock main columns,
        /// which is byte-identical to the copy Tree 1 transferred to the scheme.
        fn generateClock(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            main_source: *const tree2_main_source.Source,
            columns: *Columns,
            geometry: Geometry,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
        ) !void {
            var views: [clock_update_interaction.N_MAIN_COLUMNS][]const M31 = undefined;
            _ = try main_source.clockColumns(&workspace.statement, &views);
            var generated = try clock_update_interaction.generate(
                allocator,
                &views,
                geometry.clock_update_log,
                relations,
            );
            claim.clock_claims[geometry.clock_infra_index] = generated.claims;
            const taken = generated.takeColumns();
            for (taken) |values| columns.append(geometry.clock_update_log, values);
        }

        /// The fixed lookup tables close the registry, so their infrastructure indices
        /// are the last `LOOKUP_TABLE_COUNT` slots in declaration order.
        fn generateLookupTables(
            comptime Backend: type,
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            main_source: *const tree2_main_source.Source,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            execution_pool: ?*work_pool.WorkPool,
        ) !void {
            const capable = comptime Backend != void and @hasDecl(Backend, "supportsFrameworkInteractions");
            const device = if (capable) try Backend.supportsFrameworkInteractions() else false;
            if (!device) if (execution_pool) |pool| {
                return generateLookupTablesParallel(
                    allocator,
                    workspace,
                    columns,
                    main_source,
                    relations,
                    claim,
                    pool,
                );
            };
            const table_infra_start = workspace.statement.n_infra - component_order.LOOKUP_TABLE_COUNT;
            for (component_order.lookupTables(), 0..) |kind, table_index| {
                var timer: ?std.time.Timer = if (std.process.hasEnvVarConstant("STWO_RISCV_NATIVE_PROFILE"))
                    std.time.Timer.start() catch null
                else
                    null;
                var generated = if (capable and device)
                    try @import("../air/lookups/tables/device_interaction.zig").generate(Backend, allocator, try main_source.lookupCounter(kind), relations)
                else
                    try lookup_table_interaction.generate(allocator, try main_source.lookupCounter(kind), relations);
                claim.lookup_claims[table_infra_start + table_index] = generated.claim;
                const taken = generated.takeColumns();
                for (taken) |values| columns.append(lookup_table_schema.logSize(kind), values);
                if (timer) |*active| {
                    var bytes: usize = 0;
                    for (taken) |values| bytes += values.len * @sizeOf(@TypeOf(values[0]));
                    std.debug.print("riscv_interaction_table kind={s} generation_ns={d} owned_value_bytes={d}\n", .{
                        @tagName(kind), active.read(), bytes,
                    });
                }
            }
        }

        /// Gives each large fixed table the whole bounded pool in turn. The table
        /// generator performs a chunk-local scan plus ordered offset fix-up, while
        /// columns and claims are still appended in protocol declaration order.
        fn generateLookupTablesParallel(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            main_source: *const tree2_main_source.Source,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            pool: *work_pool.WorkPool,
        ) !void {
            const table_infra_start = workspace.statement.n_infra - component_order.LOOKUP_TABLE_COUNT;
            for (component_order.lookupTables(), 0..) |kind, table_index| {
                var timer: ?std.time.Timer = if (std.process.hasEnvVarConstant("STWO_RISCV_NATIVE_PROFILE"))
                    std.time.Timer.start() catch null
                else
                    null;
                var generated = try lookup_table_interaction.generateParallel(
                    allocator,
                    try main_source.lookupCounter(kind),
                    relations,
                    pool,
                );
                claim.lookup_claims[table_infra_start + table_index] = generated.claim;
                const taken = generated.takeColumns();
                for (taken) |values| columns.append(lookup_table_schema.logSize(kind), values);
                if (timer) |*active| {
                    var bytes: usize = 0;
                    for (taken) |values| bytes += values.len * @sizeOf(@TypeOf(values[0]));
                    std.debug.print("riscv_interaction_table kind={s} generation_ns={d} owned_value_bytes={d}\n", .{
                        @tagName(kind), active.read(), bytes,
                    });
                }
            }
        }

        fn projectedLegacyGeometry(
            geometry: native_provider_omit.ProjectedGeometryV1,
        ) Geometry {
            return .{
                .program_log_size = geometry.program_log_size,
                .merkle_log_size = geometry.merkle_log_size,
                .poseidon_log_size = 0,
                .clock_update_log = geometry.clock_update_log,
                .merkle_infra_index = geometry.merkle_infra_index,
                .poseidon_infra_index = std.math.maxInt(usize),
                .clock_infra_index = geometry.clock_infra_index,
            };
        }

        pub const Columns = @import("interaction_columns.zig").Columns;
    };
}
