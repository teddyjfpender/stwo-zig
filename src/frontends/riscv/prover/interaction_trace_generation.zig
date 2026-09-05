//! Interaction-column generators and exact-work accounting.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = @import("stwo_prover_api").stage_profile;
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const guest_interaction = @import("../air/guest_precompile/interaction.zig");
const guest_components = @import("../air/guest_precompile/component_registry.zig");
const guest_main_trace = @import("../air/guest_precompile/main_trace.zig");
const guest_proof_transcript = @import("../air/guest_precompile/proof_transcript.zig");
const guest_relations = @import("../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
const lookup_table_interaction = @import("../air/lookups/tables/interaction.zig");
const lookup_table_schema = @import("../air/lookups/tables/schema.zig");
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const BaseScalar = @import("../air/lookups/base_scalar.zig").Scalar;
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const program_interaction = @import("../air/program/interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const proof_transcript = @import("../proof_transcript.zig");
const trace_mod = @import("../runner/trace.zig");
const commitment_witness = @import("commitment_witness.zig");
const lookup_sources = @import("lookup_sources.zig");
const interaction_production = @import("interaction_trace_plan_execution_production.zig");
const interaction_witness_work = @import("interaction_witness_work.zig");
const proof_phase_meter = @import("proof_phase_meter.zig");
const proof_workspace = @import("proof_workspace.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_mod = @import("../air/statement.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const tree2_main_source = @import("tree2_main_source.zig");
const types = @import("types.zig");
const native_provider_omit = @import("memory_provider_shards/native_provider_omit_v1.zig");

const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const Relations = relation_challenges.Relations;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RunMode = types.RunMode;
const OpcodeBaseEntries = opcode_entries.Entries(BaseScalar);

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
            const generated = try program_interaction.generate(
                allocator,
                witness.program.rows,
                geometry.program_log_size,
                relations,
            );
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
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            columns: *Columns,
            main_source: *const tree2_main_source.Source,
            relations: *const Relations,
            claim: *RiscVInteractionClaim,
            execution_pool: ?*work_pool.WorkPool,
        ) !void {
            if (execution_pool) |pool| {
                return generateLookupTablesParallel(
                    allocator,
                    workspace,
                    columns,
                    main_source,
                    relations,
                    claim,
                    pool,
                );
            }
            const table_infra_start = workspace.statement.n_infra - component_order.LOOKUP_TABLE_COUNT;
            for (component_order.lookupTables(), 0..) |kind, table_index| {
                var generated = try lookup_table_interaction.generate(
                    allocator,
                    try main_source.lookupCounter(kind),
                    relations,
                );
                claim.lookup_claims[table_infra_start + table_index] = generated.claim;
                const taken = generated.takeColumns();
                for (taken) |values| columns.append(lookup_table_schema.logSize(kind), values);
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
                var generated = try lookup_table_interaction.generateParallel(
                    allocator,
                    try main_source.lookupCounter(kind),
                    relations,
                    pool,
                );
                claim.lookup_claims[table_infra_start + table_index] = generated.claim;
                const taken = generated.takeColumns();
                for (taken) |values| columns.append(lookup_table_schema.logSize(kind), values);
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

        /// Exact work of the allocation-safe sequential base generator selected by
        /// the current guest profile. Projection arithmetic is owned by the separate
        /// main-witness site; this authority covers every relation combine and LogUp
        /// normalization, inversion, and prefix operation performed by Tree 2.
        pub fn sequentialBaseWorkCounts(
            statement: *const statement_mod.RiscVStatement,
            witness: *const CommitmentWitness,
            geometry: Geometry,
            lookup_v2: ?*const lookup_physical_v2.Manifest,
        ) !interaction_witness_work.Counts {
            var counts = interaction_witness_work.Counts{};

            for (statement.component_descs[0..statement.n_components]) |descriptor| {
                const size = try workDomainSize(descriptor.log_size);
                var zeros = [_]BaseScalar{BaseScalar.zero()} ** trace_mod.MAX_FAMILY_COLUMNS;
                const list = try OpcodeBaseEntries.fromMain(
                    descriptor.family,
                    zeros[0..trace_mod.nColumnsForFamily(descriptor.family)],
                );
                var relation_inputs: usize = 0;
                for (list.entries[0..list.len]) |entry| {
                    relation_inputs = try workAddUsize(relation_inputs, entry.arity);
                }
                try interaction_witness_work.observeRelationRows(
                    &counts,
                    size,
                    list.len,
                    relation_inputs,
                );
                const n_batches, const paired_batches = if (lookup_v2) |manifest| blk: {
                    const physical = manifest.entryForFamily(descriptor.family);
                    try lookup_physical_v2.validatePinnedEntry(physical);
                    if (physical.lookup_authority.entry_count != list.len)
                        return error.InteractionWorkSourceMismatch;
                    var paired: usize = 0;
                    for (physical.activeBatches()) |batch| {
                        paired += @intFromBool(batch.entry_count == 2);
                    }
                    break :blk .{ physical.activeBatches().len, paired };
                } else .{
                    list.batchCount(),
                    if (list.batch_size == 1) 0 else list.len - list.batchCount(),
                };
                try observeSequentialBatchLogup(
                    &counts,
                    size,
                    n_batches,
                    paired_batches,
                    opcode_interaction.CHUNK_ROWS,
                );
            }

            try interaction_witness_work.observeRelationRows(
                &counts,
                witness.program.rows.len,
                7,
                24,
            );
            try observeDirectLogup(
                &counts,
                try workDomainSize(geometry.program_log_size),
                program_interaction.N_SUMS,
            );

            for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
                if (descriptor.kind != .memory) continue;
                try interaction_witness_work.observeRelationRows(
                    &counts,
                    descriptor.n_rows,
                    7,
                    27,
                );
                try observeDirectLogup(
                    &counts,
                    try workDomainSize(descriptor.log_size),
                    memory_interaction.N_SUMS,
                );
            }

            try interaction_witness_work.observeRelationRows(
                &counts,
                witness.merkleRows().len,
                5,
                44,
            );
            try observeDirectLogup(
                &counts,
                try workDomainSize(geometry.merkle_log_size),
                merkle_node.N_SUMS,
            );

            try interaction_witness_work.observeRelationRows(
                &counts,
                witness.poseidonCalls().len,
                4,
                80,
            );
            try observeDirectLogup(
                &counts,
                try workDomainSize(geometry.poseidon_log_size),
                poseidon2_air.N_SUMS,
            );

            // The live clock generator loops over each sum and reconstructs both
            // pairs inside that loop, so its four denominator combines execute twice.
            const clock_size = try workDomainSize(geometry.clock_update_log);
            try interaction_witness_work.observeRelationRows(
                &counts,
                try workMulUsize(clock_size, clock_update_interaction.N_SUMS),
                4,
                17,
            );
            for (0..clock_update_interaction.N_SUMS) |_| {
                try observeSequentialBatchLogup(
                    &counts,
                    clock_size,
                    1,
                    1,
                    clock_update_interaction.CHUNK_ROWS,
                );
            }

            // `generateInto` first proves every denominator non-zero, then rebuilds
            // each denominator during its bounded generation pass.
            for (component_order.lookupTables()) |kind| {
                const size = lookup_table_schema.size(kind);
                try interaction_witness_work.observeRelationRows(
                    &counts,
                    try workMulUsize(size, 2),
                    1,
                    lookup_table_schema.arity(kind),
                );
                try observeSequentialBatchLogup(
                    &counts,
                    size,
                    1,
                    0,
                    lookup_table_interaction.CHUNK_ROWS,
                );
            }
            return counts;
        }

        pub fn guestInteractionWorkCounts(
            active_rows: u32,
        ) !interaction_witness_work.Counts {
            var counts = interaction_witness_work.Counts{};
            var caller_inputs: usize = 0;
            for (guest_components.caller_events) |event| {
                if (event.numerator == .zero_in_guest_mode)
                    return error.InteractionWorkSourceMismatch;
                caller_inputs = try workAddUsize(caller_inputs, event.arity);
            }
            var paired_batches: usize = 0;
            for (guest_components.caller_batches) |batch| {
                paired_batches += @intFromBool(batch.second_event != null);
            }
            const provider_event = guest_components.provider_events[3];
            if (provider_event.arity != guest_relations.guest_relation_arity or
                paired_batches + 1 != guest_interaction.caller_batch_count)
            {
                return error.InteractionWorkSourceMismatch;
            }
            const rows: usize = @intCast(active_rows);
            try interaction_witness_work.observeRelationRows(
                &counts,
                rows,
                guest_interaction.caller_event_count + 1,
                try workAddUsize(caller_inputs, provider_event.arity),
            );
            try interaction_witness_work.observeLogupTerms(
                &counts,
                try workMulUsize(rows, paired_batches),
                try workMulUsize(rows, guest_interaction.total_batch_count),
                0,
            );
            var row_start: usize = 0;
            while (row_start < rows) {
                const chunk_len = @min(guest_interaction.chunk_rows, rows - row_start);
                try interaction_witness_work.observeBatchInverse(
                    &counts,
                    try workMulUsize(guest_interaction.total_batch_count, chunk_len),
                );
                row_start += chunk_len;
            }
            return counts;
        }

        fn observeDirectLogup(
            counts: *interaction_witness_work.Counts,
            rows: usize,
            n_sums: usize,
        ) !void {
            const terms = try workMulUsize(rows, n_sums);
            try interaction_witness_work.observeLogupTerms(
                counts,
                terms,
                terms,
                terms,
            );
        }

        fn observeSequentialBatchLogup(
            counts: *interaction_witness_work.Counts,
            rows: usize,
            n_batches: usize,
            paired_batches: usize,
            chunk_rows: usize,
        ) !void {
            try interaction_witness_work.observeLogupTerms(
                counts,
                try workMulUsize(rows, paired_batches),
                try workMulUsize(rows, n_batches),
                0,
            );
            var row_start: usize = 0;
            while (row_start < rows) {
                const chunk_len = @min(chunk_rows, rows - row_start);
                try interaction_witness_work.observeBatchInverse(
                    counts,
                    try workMulUsize(n_batches, chunk_len),
                );
                row_start += chunk_len;
            }
        }

        fn workDomainSize(log_size: u32) !usize {
            if (log_size >= @bitSizeOf(usize)) return error.InteractionWorkOverflow;
            return @as(usize, 1) << @intCast(log_size);
        }

        fn workAddUsize(lhs: usize, rhs: usize) !usize {
            return std.math.add(usize, lhs, rhs) catch error.InteractionWorkOverflow;
        }

        fn workMulUsize(lhs: usize, rhs: usize) !usize {
            return std.math.mul(usize, lhs, rhs) catch error.InteractionWorkOverflow;
        }

        /// The committed column array, filled strictly front to back.
        ///
        /// A prefix counter is enough here (unlike Tree 1, which writes two disjoint
        /// regions) because interaction columns are appended in declaration order and
        /// never addressed absolutely.
        pub const Columns = struct {
            values: []prover_pcs.ColumnEvaluation,
            filled: usize,
            moved: bool,

            pub fn init(allocator: std.mem.Allocator, n_interaction: usize) !Columns {
                return .{
                    .values = try allocator.alloc(prover_pcs.ColumnEvaluation, n_interaction),
                    .filled = 0,
                    .moved = false,
                };
            }

            pub fn append(self: *Columns, log_size: u32, values: []M31) void {
                self.values[self.filled] = .{ .log_size = log_size, .values = values };
                self.filled += 1;
            }

            /// Transfers one complete generated interaction block into the
            /// declaration-ordered commitment. The caller retains ownership
            /// only when validation fails before the first append.
            pub fn appendGenerated(
                self: *Columns,
                log_size: u32,
                generated: []const []M31,
            ) !void {
                if (self.filled > self.values.len or
                    generated.len > self.values.len - self.filled)
                {
                    return error.InvalidTraceShape;
                }
                for (generated) |values| self.append(log_size, values);
            }

            pub fn reserveGuest(
                self: *Columns,
                allocator: std.mem.Allocator,
                log_size: u32,
            ) !guest_interaction.Destinations {
                const count = guest_interaction.total_column_count;
                if (self.filled > self.values.len or count > self.values.len - self.filled or
                    log_size >= @bitSizeOf(usize))
                {
                    return error.InvalidTraceShape;
                }
                const start = self.filled;
                const domain_size = @as(usize, 1) << @intCast(log_size);
                var initialized: usize = 0;
                errdefer {
                    for (self.values[start .. start + initialized]) |column| {
                        allocator.free(@constCast(column.values));
                    }
                    self.filled = start;
                }
                while (initialized < count) : (initialized += 1) {
                    self.values[start + initialized] = .{
                        .log_size = log_size,
                        .values = try allocator.alloc(M31, domain_size),
                    };
                    self.filled += 1;
                }
                var result: guest_interaction.Destinations = undefined;
                for (&result.caller, 0..) |*destination, index| {
                    destination.* = @constCast(self.values[start + index].values);
                }
                const provider_start = start + guest_interaction.caller_column_count;
                for (&result.provider, 0..) |*destination, index| {
                    destination.* = @constCast(self.values[provider_start + index].values);
                }
                return result;
            }

            /// Releases the filled prefix only while this array still owns it: after
            /// `moved` the commitment scheme does.
            pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
                if (self.moved) return;
                for (self.values[0..self.filled]) |column| allocator.free(@constCast(column.values));
                allocator.free(self.values);
            }
        };
    };
}
