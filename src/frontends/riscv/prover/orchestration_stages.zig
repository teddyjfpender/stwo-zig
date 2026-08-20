//! Proof-stage sequencing and derived statement ownership.
//!     Engine, allocator, config, &exec_trace, &state_chain, &rw_memory, null, public_data,
//! );
//! try verifyRiscVWithEngine(Engine, allocator, config, result.statement, result.proof, result.interaction_claim);
//! ```

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_engine").engine;
const work_pool = @import("stwo_prover_engine").work_pool;
const prover_api = @import("stwo_prover_api");
const stage_profile = @import("stwo_prover_api").stage_profile;
const lookup_physical_v2 = @import("../air/lang/lookup_physical_manifest_v2.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const trace_mod = @import("../runner/trace.zig");
const memory_state = @import("../runner/memory_state.zig");
const runner_result = @import("../runner/result.zig");
const state_chain = @import("../runner/state_chain.zig");
const commitment_witness = @import("commitment_witness.zig");
const interaction_trace = @import("interaction_trace.zig");
const main_trace = @import("main_trace.zig");
const preprocessed_trace = @import("preprocessed.zig");
const proof_finalize = @import("proof_finalize.zig");
const proof_phase_meter = @import("proof_phase_meter.zig");
const poseidon_witness_work = @import("poseidon_witness_work.zig");
const proof_workspace = @import("proof_workspace.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const statement_geometry = @import("statement_geometry.zig");
const statement_validation = @import("statement_validation.zig");
const test_trace_dump = @import("test_trace_dump.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const types = @import("types.zig");

const CommitmentWitness = commitment_witness.CommitmentWitness;
const Geometry = statement_geometry.Geometry;
const ProofWorkspace = proof_workspace.ProofWorkspace;
const PublicData = types.PublicData;
const ProverError = types.ProverError;
const RiscVInteractionClaim = types.RiscVInteractionClaim;
const RiscVStatement = types.RiscVStatement;
const RunMode = types.RunMode;
const RunOutputForEngine = types.RunOutputForEngine;

pub fn Ops(comptime Owner: type) type {
    const LookupLayoutV2 = Owner.LookupLayoutV2;
    const ProofExecutionPool = Owner.ProofExecutionPool;
    const ExecutionOptions = Owner.ExecutionOptions;
    const ExecutionOptionsV2 = Owner.ExecutionOptionsV2;
    const TestWitnessMutation = Owner.TestWitnessMutation;
    const TestTraceDump = Owner.TestTraceDump;
    const ProveOutputV2ForEngine = types.ProveOutputV2ForEngine;

    return struct {
        pub fn proveStagesV2(
            comptime Engine: type,
            comptime lookup_layout: LookupLayoutV2,
            workspace: *ProofWorkspace,
            output: *ProveOutputV2ForEngine(Engine),
            allocator: std.mem.Allocator,
            pcs_config: pcs_core.PcsConfig,
            result: *const runner_result.SegmentResult,
            recorder: ?*stage_profile.Recorder,
            public_data: public_data_v2.PublicDataV2,
            transcript_channel: *Engine.Channel,
            execution: ExecutionOptionsV2,
        ) !void {
            const exec_trace = &result.execution_trace;
            const chain = &result.state_chain_tracker;
            if (exec_trace.step_count == 0) return ProverError.EmptyTrace;

            var execution_pool: ProofExecutionPool = .{};
            try execution_pool.initInPlace(allocator, execution.cpu);
            defer execution_pool.deinit();

            var derived = try deriveV2(
                allocator,
                workspace,
                result,
                recorder,
                public_data,
            );
            defer derived.witness.deinit(allocator);
            const witness = &derived.witness;
            const geometry = derived.geometry;
            const native_statement = &derived.statement;
            const core_statement = &workspace.statement;

            if (execution.statement_admission) |admission|
                try admission.admit(native_statement);

            // Do not invoke V1's specialized channel hook: it binds a different public
            // statement and exists only for frozen recursive V1 schedules.
            pcs_config.mixInto(transcript_channel);
            try statement_v2.mixIntoNativeTranscript(
                &native_statement.public_data,
                transcript_channel,
            );
            var lookup_manifest: lookup_physical_v2.Manifest = undefined;
            var authenticated_lookup: lookup_physical_v2.AuthenticatedStatement =
                undefined;
            if (comptime lookup_layout == .authenticated_physical_v2) {
                lookup_manifest = lookup_physical_v2.Manifest.native();
                authenticated_lookup = try lookup_physical_v2.AuthenticatedStatement.init(
                    core_statement,
                    &lookup_manifest,
                );
                authenticated_lookup.mixInto(transcript_channel);
            }

            var scheme = try Engine.init(allocator, pcs_config);
            var scheme_owned = true;
            defer if (scheme_owned) Engine.deinit(&scheme, allocator);

            var ignored_tree0: ?relation_diagnostic.RetainedTree = null;
            defer if (ignored_tree0) |*tree| tree.deinit(allocator);
            var ignored_tree1: ?relation_diagnostic.RetainedTree = null;
            defer if (ignored_tree1) |*tree| tree.deinit(allocator);

            try preprocessed_trace.generateAndCommit(
                Engine,
                .prove,
                allocator,
                core_statement,
                &scheme,
                transcript_channel,
                recorder,
                null,
                &ignored_tree0,
                null,
            );

            var retained = try main_trace.generateAndCommitWithExecution(
                Engine,
                .prove,
                allocator,
                workspace,
                &scheme,
                transcript_channel,
                recorder,
                exec_trace,
                witness,
                geometry,
                chain,
                null,
                null,
                &ignored_tree1,
                execution.cpu,
                execution_pool.get(),
                null,
            );
            defer retained.deinit(allocator, workspace);

            logProofGeometry(core_statement, geometry, witness.poseidonCalls().len);
            const transcript_prefix = try interaction_trace.drawChallenges(
                Engine,
                .prove,
                allocator,
                transcript_channel,
                core_statement,
                recorder,
            );

            const interaction_claim = try allocator.create(RiscVInteractionClaim);
            var interaction_claim_owned = true;
            defer if (interaction_claim_owned) allocator.destroy(interaction_claim);
            const tree2_source = retained.tree2Source(workspace);
            if (comptime lookup_layout == .authenticated_physical_v2) {
                try interaction_trace.generateAndCommitAuthenticatedLookupV2(
                    Engine,
                    allocator,
                    workspace,
                    &scheme,
                    transcript_channel,
                    recorder,
                    witness,
                    geometry,
                    &tree2_source,
                    &transcript_prefix,
                    interaction_claim,
                    null,
                    &lookup_manifest,
                    &authenticated_lookup,
                );
            } else {
                try interaction_trace.generateAndCommitWithExecution(
                    Engine,
                    allocator,
                    workspace,
                    &scheme,
                    transcript_channel,
                    recorder,
                    witness,
                    geometry,
                    &tree2_source,
                    &transcript_prefix,
                    interaction_claim,
                    null,
                    execution.cpu,
                    execution_pool.get(),
                    null,
                );
            }

            scheme_owned = false;
            const n_main = core_statement.nOpcodeMainColumns() +
                core_statement.nInfraColumns();
            const n_interaction = if (comptime lookup_layout == .authenticated_physical_v2)
                try authenticated_lookup.totalInteractionColumns(
                    core_statement,
                    &lookup_manifest,
                )
            else
                core_statement.nInteractionColumns();
            var proof = if (comptime lookup_layout == .authenticated_physical_v2)
                try proof_finalize.proveAuthenticatedLookupV2(
                    Engine,
                    allocator,
                    .{
                        .recorder = recorder,
                        .cpu_composition_execution = execution.cpu,
                    },
                    scheme,
                    transcript_channel,
                    workspace,
                    &transcript_prefix.relations,
                    interaction_claim,
                    n_main,
                    n_interaction,
                    &lookup_manifest,
                    &authenticated_lookup,
                )
            else
                try proof_finalize.proveWithOptions(
                    Engine,
                    allocator,
                    .{
                        .recorder = recorder,
                        .cpu_composition_execution = execution.cpu,
                    },
                    scheme,
                    transcript_channel,
                    workspace,
                    &transcript_prefix.relations,
                    interaction_claim,
                    n_main,
                    n_interaction,
                );
            errdefer proof.deinit(allocator);
            interaction_claim_owned = false;
            work_pool.recordProofPublicationForTest(execution_pool.get());
            output.* = .{
                .statement = native_statement.*,
                .proof = proof,
                .interaction_claim = interaction_claim,
            };
        }

        /// Executes every proving stage against workspace-resident storage. `!void` and
        /// the out-pointer are deliberate: see the module note on frame slots.
        ///
        /// The `defer`s here, and not inside the stages, are the ones whose buffers are
        /// still borrowed by a *later* stage: composition reads the interaction scratch,
        /// and `Engine.prove` reads the components that borrow it, so nothing acquired
        /// for Tree 2 may be released before proving returns.
        pub fn proveStages(
            comptime Engine: type,
            comptime mode: RunMode,
            workspace: *ProofWorkspace,
            output: *RunOutputForEngine(Engine, mode),
            allocator: std.mem.Allocator,
            pcs_config: pcs_core.PcsConfig,
            exec_trace: *const trace_mod.Trace,
            opt_chain: ?*const state_chain.StateChainTracker,
            opt_memory: ?*const memory_state.Snapshot,
            recorder: ?*stage_profile.Recorder,
            public_data: PublicData,
            channel: *Engine.Channel,
            test_mutation: ?TestWitnessMutation,
            test_dump: ?*TestTraceDump,
            execution: ExecutionOptions,
            phase_meter: ?*proof_phase_meter.Meter,
        ) !void {
            if (exec_trace.step_count == 0) return ProverError.EmptyTrace;

            // One admitted pool spans Tree 0, Tree 1, Tree 2, quotient composition,
            // and commitment openings. Every stage drains its work before this owner
            // is released; no nested stage may create an independent worker budget.
            var execution_pool: ProofExecutionPool = .{};
            try execution_pool.initInPlace(allocator, execution.cpu);
            defer execution_pool.deinit();

            var derived = try derive(
                mode,
                allocator,
                workspace,
                exec_trace,
                opt_chain,
                opt_memory,
                recorder,
                public_data,
                phase_meter,
            );
            defer derived.witness.deinit(allocator);
            const witness = &derived.witness;
            const geometry = derived.geometry;
            const statement = &workspace.statement;

            if (execution.statement_admission) |admission|
                try admission.admit(statement);

            // Security geometry is part of the RISC-V Fiat–Shamir statement. This
            // prevents a proof under one profile from sharing a transcript prefix with
            // another profile even when every execution field is identical.
            if (comptime @hasDecl(Engine.Channel, "bindRiscVTranscript")) {
                try channel.bindRiscVTranscript(pcs_config, &statement.public_data);
            } else {
                pcs_config.mixInto(channel);
                statement.public_data.mixInto(channel);
            }

            var scheme = try Engine.init(allocator, pcs_config);
            var scheme_owned = true;
            defer if (scheme_owned) Engine.deinit(&scheme, allocator);

            var retained_tree0: ?relation_diagnostic.RetainedTree = null;
            defer if (retained_tree0) |*tree| tree.deinit(allocator);
            var retained_tree1: ?relation_diagnostic.RetainedTree = null;
            defer if (retained_tree1) |*tree| tree.deinit(allocator);

            try preprocessed_trace.generateAndCommit(
                Engine,
                mode,
                allocator,
                statement,
                &scheme,
                channel,
                recorder,
                test_mutation,
                &retained_tree0,
                phase_meter,
            );

            var retained = try main_trace.generateAndCommitWithExecution(
                Engine,
                mode,
                allocator,
                workspace,
                &scheme,
                channel,
                recorder,
                exec_trace,
                witness,
                geometry,
                opt_chain,
                test_mutation,
                test_dump,
                &retained_tree1,
                execution.cpu,
                execution_pool.get(),
                phase_meter,
            );
            defer retained.deinit(allocator, workspace);

            if (comptime mode == .prove) logProofGeometry(statement, geometry, witness.poseidonCalls().len);

            const transcript_prefix = try interaction_trace.drawChallenges(
                Engine,
                mode,
                allocator,
                channel,
                statement,
                recorder,
            );

            const interaction_claim = try allocator.create(RiscVInteractionClaim);
            var interaction_claim_owned = true;
            defer if (interaction_claim_owned) allocator.destroy(interaction_claim);
            const tree2_source = retained.tree2Source(workspace);

            try interaction_trace.generateAndCommitWithExecution(
                Engine,
                allocator,
                workspace,
                &scheme,
                channel,
                recorder,
                witness,
                geometry,
                &tree2_source,
                &transcript_prefix,
                interaction_claim,
                test_mutation,
                execution.cpu,
                execution_pool.get(),
                phase_meter,
            );

            // Exported here and not at the commit point because this is the first
            // instant at which all four exported artefacts coexist: the opcode buffers
            // Tree 1 was copied from, the challenges Tree 2 was built under, and the
            // claims Tree 2 produced. The run continues to a real proof afterwards.
            if (test_dump) |dump| try dump.record(
                statement,
                &transcript_prefix.relations,
                interaction_claim,
            );

            if (comptime mode == .relation_diagnostic) {
                if (phase_meter) |meter| try meter.requireComplete();
                output.* = try buildDiagnostic(
                    Engine,
                    allocator,
                    statement,
                    &scheme,
                    &retained_tree0.?,
                    &retained_tree1.?,
                    transcript_prefix.relations,
                    interaction_claim,
                );
                return;
            }

            scheme_owned = false;
            var proof = try proof_finalize.proveWithOptions(
                Engine,
                allocator,
                .{
                    .recorder = recorder,
                    .cpu_composition_execution = execution.cpu,
                },
                scheme,
                channel,
                workspace,
                &transcript_prefix.relations,
                interaction_claim,
                statement.nOpcodeMainColumns() + statement.nInfraColumns(),
                statement.nInteractionColumns(),
            );
            errdefer proof.deinit(allocator);
            if (phase_meter) |meter| try meter.requireComplete();
            if (comptime @hasDecl(Engine.Channel, "completeRiscVTranscript"))
                try channel.completeRiscVTranscript();
            interaction_claim_owned = false;
            work_pool.recordProofPublicationForTest(execution_pool.get());
            output.* = .{
                .statement = statement.*,
                .proof = proof,
                .interaction_claim = interaction_claim,
            };
        }

        /// Everything the proof is derived from, before the transcript opens.
        const Derived = struct {
            witness: CommitmentWitness,
            geometry: Geometry,
        };

        const DerivedV2 = struct {
            witness: CommitmentWitness,
            geometry: Geometry,
            statement: statement_v2.RiscVStatementV2,
        };

        /// Derives the commitment witness and admits the statement it implies.
        ///
        /// Nothing here touches the channel. That is the point of the boundary: the
        /// whole derivation is a function of the execution alone, so a statement the
        /// witness does not support is rejected before a single transcript event has
        /// been mixed, and a rejected run leaves the caller's channel untouched.
        ///
        /// The witness is **transferred** to the caller, which releases it once every
        /// stage that takes views into it has finished.
        fn derive(
            comptime mode: RunMode,
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            exec_trace: *const trace_mod.Trace,
            opt_chain: ?*const state_chain.StateChainTracker,
            opt_memory: ?*const memory_state.Snapshot,
            recorder: ?*stage_profile.Recorder,
            public_data: PublicData,
            phase_meter: ?*proof_phase_meter.Meter,
        ) !Derived {
            var bound_public_data = public_data;
            try commitment_witness.bindCompletion(&bound_public_data, exec_trace.final_pc, opt_memory);

            var witness_region: ?proof_phase_meter.WitnessRegion =
                if (phase_meter) |meter| try meter.begin() else null;
            errdefer if (witness_region) |*region| region.abort();

            var poseidon_authority = try poseidon_witness_work.plan(recorder);
            var witness = if (poseidon_authority) |*authority|
                try CommitmentWitness.buildWithWorkReceipt(
                    allocator,
                    exec_trace,
                    opt_memory,
                    bound_public_data.completion.?,
                    authority,
                )
            else
                try CommitmentWitness.build(
                    allocator,
                    exec_trace,
                    opt_memory,
                    bound_public_data.completion.?,
                );
            errdefer witness.deinit(allocator);
            if (witness_region) |*region| try region.finish();

            // The two policies are one-to-one with the run modes; `statement_validation`
            // owns whatever difference they carry.
            const policy: statement_validation.AdmissionPolicy = switch (mode) {
                .prove => .proof,
                .relation_diagnostic => .relation_diagnostic,
            };
            var geometry_region: ?proof_phase_meter.WitnessRegion =
                if (phase_meter) |meter| try meter.begin() else null;
            errdefer if (geometry_region) |*region| region.abort();

            const geometry = try statement_geometry.build(
                allocator,
                workspace,
                exec_trace,
                &witness,
                opt_chain,
                bound_public_data,
                policy,
            );
            if (geometry_region) |*region| try region.finish();
            return .{ .witness = witness, .geometry = geometry };
        }

        pub fn deriveV2(
            allocator: std.mem.Allocator,
            workspace: *ProofWorkspace,
            result: *const runner_result.SegmentResult,
            recorder: ?*stage_profile.Recorder,
            public_data: public_data_v2.PublicDataV2,
        ) !DerivedV2 {
            var poseidon_authority = try poseidon_witness_work.plan(recorder);
            var witness = if (poseidon_authority) |*authority|
                try CommitmentWitness.buildV2WithWorkReceipt(
                    allocator,
                    &result.execution_trace,
                    &result.rw_memory,
                    &public_data,
                    authority,
                )
            else
                try CommitmentWitness.buildV2(
                    allocator,
                    &result.execution_trace,
                    &result.rw_memory,
                    &public_data,
                );
            errdefer witness.deinit(allocator);

            const built = try statement_geometry.buildV2(
                allocator,
                workspace,
                &result.execution_trace,
                &witness,
                &result.state_chain_tracker,
                public_data,
                .proof,
            );
            try built.statement.validateSegmentResult(result);
            return .{
                .witness = witness,
                .geometry = built.base,
                .statement = built.statement,
            };
        }

        /// CP-11 relation evidence over the three roots this run committed.
        ///
        /// The tree-shape guard is not defensive: `relation_diagnostic` indexes the
        /// roots positionally, so a scheme that committed a different number of trees
        /// would silently attribute one tree's root to another.
        fn buildDiagnostic(
            comptime Engine: type,
            allocator: std.mem.Allocator,
            statement: *const RiscVStatement,
            scheme: *const Engine.Scheme,
            tree0: *const relation_diagnostic.RetainedTree,
            tree1: *const relation_diagnostic.RetainedTree,
            relations: relation_challenges.Relations,
            claim: *const RiscVInteractionClaim,
        ) !types.RelationDiagnostic {
            if (scheme.trees.items.len != 3) return error.InvalidTreeShape;
            return relation_diagnostic.build(allocator, statement, tree0, tree1, .{
                scheme.trees.items[0].root(),
                scheme.trees.items[1].root(),
                scheme.trees.items[2].root(),
            }, relations, claim);
        }

        /// Column counts of the committed trees, once per proving run.
        fn logProofGeometry(
            statement: *const RiscVStatement,
            geometry: Geometry,
            n_poseidon_calls: usize,
        ) void {
            const n_opcode_main = statement.nOpcodeMainColumns();
            const n_infra_main = statement.nInfraColumns();
            std.log.info("Columns: opcode={d} infra={d} total tree1={d} interaction={d}", .{
                n_opcode_main,
                n_infra_main,
                n_opcode_main + n_infra_main,
                statement.nInteractionColumns(),
            });
            std.log.info("Poseidon2 Merkle: {d} exact sparse-node calls, poseidon_log_size={d}, merkle_log_size={d}", .{
                n_poseidon_calls,
                geometry.poseidon_log_size,
                geometry.merkle_log_size,
            });
        }
    };
}
