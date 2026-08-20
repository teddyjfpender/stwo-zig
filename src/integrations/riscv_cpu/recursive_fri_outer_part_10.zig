//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const prover_work_pool = context.d_prover_work_pool;
        const recursion = context.d_recursion;
        const vm_input_air = context.d_vm_input_air;
        const vm_input_witness = context.d_vm_input_witness;
        const composition_control_air = context.d_composition_control_air;
        const composition_control_witness = context.d_composition_control_witness;
        const circuit_mod = context.d_circuit_mod;
        const query_bits_air = context.d_query_bits_air;
        const query_bits_witness = context.d_query_bits_witness;
        const query_mapping_air = context.d_query_mapping_air;
        const query_mapping_witness = context.d_query_mapping_witness;
        const merkle_root_air = context.d_merkle_root_air;
        const merkle_root_witness = context.d_merkle_root_witness;
        const trace_merkle_air = context.d_trace_merkle_air;
        const trace_merkle_witness = context.d_trace_merkle_witness;
        const pcs_circuit_mod = context.d_pcs_circuit_mod;
        const pcs_air = context.d_pcs_air;
        const pcs_witness = context.d_pcs_witness;
        const fri_leaf_air = context.d_fri_leaf_air;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const fri_node_air = context.d_fri_node_air;
        const fri_node_witness = context.d_fri_node_witness;
        const fri_anchor_air = context.d_fri_anchor_air;
        const fri_anchor_witness = context.d_fri_anchor_witness;
        const control_air = context.d_control_air;
        const control_witness = context.d_control_witness;
        const schedule = context.d_schedule;
        const input_air = context.d_input_air;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const multiply_air = context.d_multiply_air;
        const multiply_witness = context.d_multiply_witness;
        const inverse_air = context.d_inverse_air;
        const inverse_witness = context.d_inverse_witness;
        const linear_air = context.d_linear_air;
        const linear_witness = context.d_linear_witness;
        const merkle_path_air = context.d_merkle_path_air;
        const merkle_path_witness = context.d_merkle_path_witness;
        const manifest_mod = context.d_manifest_mod;
        const poseidon2_authority = context.d_poseidon2_authority;
        const SegmentTranscriptSource = context.d_SegmentTranscriptSource;
        const SegmentLeafOuterBundle = context.d_SegmentLeafOuterBundle;
        const LogIndex = context.d_LogIndex;
        const InputRelation = context.d_InputRelation;
        const VmInputRelation = context.d_VmInputRelation;
        const CompositionControlRelation = context.d_CompositionControlRelation;
        const QueryBitsRelation = context.d_QueryBitsRelation;
        const QueryMappingRelation = context.d_QueryMappingRelation;
        const MerkleRootRelation = context.d_MerkleRootRelation;
        const TraceMerkleRelation = context.d_TraceMerkleRelation;
        const PcsRelation = context.d_PcsRelation;
        const FriLeafRelation = context.d_FriLeafRelation;
        const FriNodeRelation = context.d_FriNodeRelation;
        const FriAnchorRelation = context.d_FriAnchorRelation;
        const ControlRelation = context.d_ControlRelation;
        const MultiplyRelation = context.d_MultiplyRelation;
        const InverseRelation = context.d_InverseRelation;
        const LinearRelation = context.d_LinearRelation;
        const MerklePathRelation = context.d_MerklePathRelation;
        const VerifierPlans = context.d_VerifierPlans;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const AssemblyProfile = context.d_AssemblyProfile;
        const Claims = context.d_Claims;
        const initAuthority = context.d_initAuthority;

        pub const ProofBundle = struct {
            proof: recursion.engine.Proof,
            claims: Claims,
            log_sizes: [LogIndex.count]u32,
            geometry: [4]u32,
            transcript_draws: usize,
            assembly_ns: u64,
            assembly_profile: AssemblyProfile,
            stark_prove_ns: u64,
            poseidon2_call_count: u32,
            pcs_graph_nodes: usize,
            pcs_graph_inputs: usize,
            pcs_graph_outputs: usize,
            arithmetic_active_counts: [3]usize,
            arithmetic_capacity_rows: [3]usize,
        };

        /// Stable-address owner for the bounded pool visible to every parallel-aware
        /// stage in this proving transaction. A one-worker request deliberately binds
        /// no pool and therefore remains the exact serial control.
        pub const ProofExecutionPool = struct {
            pool: prover_work_pool.WorkPool = undefined,
            binding: prover_work_pool.ScopedPoolBinding = undefined,
            requested_worker_count: usize = 1,
            pool_initialized: bool = false,
            binding_initialized: bool = false,

            fn initInPlace(
                self: *ProofExecutionPool,
                allocator: std.mem.Allocator,
                worker_count: usize,
            ) !void {
                self.* = .{};
                _ = try prover_work_pool.WorkerBudget.init(worker_count);
                self.requested_worker_count = worker_count;
                if (worker_count == 1) return;
                try self.pool.initInPlaceWithOptions(.{
                    .worker_count = worker_count,
                    .stack_size = prover_work_pool.WORKER_STACK_SIZE,
                    .backing_allocator = allocator,
                });
                self.pool_initialized = true;
                errdefer {
                    self.pool.deinit();
                    self.pool_initialized = false;
                }
                self.binding = try prover_work_pool.ScopedPoolBinding.init(&self.pool);
                self.binding_initialized = true;
            }

            /// Resolves the same coordinator-thread binding consumed synchronously by
            /// Merkle commitments and PCS sampled-value evaluation.  N=1 deliberately
            /// avoids `getGlobalPool`: production resolution may lazily create the
            /// ambient process pool, while this transaction's serial test control must
            /// remain a no-pool execution.
            fn visibleWorkerCount(self: *ProofExecutionPool) !usize {
                if (self.requested_worker_count == 1) {
                    if (self.pool_initialized or self.binding_initialized)
                        return error.WorkerPoolMismatch;
                    return 1;
                }
                if (!self.pool_initialized or !self.binding_initialized)
                    return error.WorkerPoolMismatch;
                const visible = prover_work_pool.getGlobalPool() orelse
                    return error.WorkerPoolMismatch;
                if (visible != &self.pool or
                    visible.workerCount() != self.requested_worker_count)
                {
                    return error.WorkerPoolMismatch;
                }
                return visible.workerCount();
            }

            fn deinit(self: *ProofExecutionPool) void {
                if (self.binding_initialized) {
                    self.binding.deinit();
                    self.binding_initialized = false;
                }
                if (self.pool_initialized) {
                    self.pool.deinit();
                    self.pool_initialized = false;
                }
            }
        };

        /// Relation rows whose main values are captured directly from the exact
        /// column buffers later committed as Tree 1. Keeping these five schedules
        /// across the Tree-1 commitment avoids re-running stateful Merkle witnesses
        /// and, critically, avoids authenticating an O(n) schedule once per row.
        pub const PreparedRelationRows = struct {
            allocator: std.mem.Allocator,
            vm_input: []VmInputRelation.Row,
            trace_merkle: []TraceMerkleRelation.Row,
            fri_leaf: []FriLeafRelation.Row,
            fri_node: []FriNodeRelation.Row,
            fri_anchor: []FriAnchorRelation.Row,
            control: []ControlRelation.Row,

            pub fn init(allocator: std.mem.Allocator, authority: *const Authority) !PreparedRelationRows {
                const vm_input_count = if (authority.vm_air) |vm_air|
                    vm_air.prepared.preprocessing.rows.len
                else
                    0;
                const vm_input = try allocator.alloc(VmInputRelation.Row, vm_input_count);
                errdefer allocator.free(vm_input);
                if (authority.vm_air) |vm_air| {
                    for (
                        vm_air.prepared.preprocessing.rows,
                        vm_air.prepared.schedule_values,
                        vm_input,
                    ) |row, value, *destination| {
                        destination.* = try vm_input_witness.logicalRow(
                            row,
                            value,
                            .segment_leaf,
                        );
                    }
                }
                const trace_merkle = try allocator.alloc(
                    TraceMerkleRelation.Row,
                    authority.trace_merkle_preprocessing.rows.len,
                );
                errdefer allocator.free(trace_merkle);
                const fri_leaf = try allocator.alloc(
                    FriLeafRelation.Row,
                    authority.fri_leaf_preprocessing.rows.len,
                );
                errdefer allocator.free(fri_leaf);
                const fri_node = try allocator.alloc(
                    FriNodeRelation.Row,
                    authority.fri_node_preprocessing.rows.len,
                );
                errdefer allocator.free(fri_node);
                const fri_anchor = try allocator.alloc(
                    FriAnchorRelation.Row,
                    authority.fri_anchor_preprocessing.rows.len,
                );
                errdefer allocator.free(fri_anchor);
                const control = try allocator.alloc(
                    ControlRelation.Row,
                    authority.control_preprocessing.rows.len,
                );
                errdefer allocator.free(control);
                return .{
                    .allocator = allocator,
                    .vm_input = vm_input,
                    .trace_merkle = trace_merkle,
                    .fri_leaf = fri_leaf,
                    .fri_node = fri_node,
                    .fri_anchor = fri_anchor,
                    .control = control,
                };
            }

            pub fn deinit(self: *PreparedRelationRows) void {
                self.allocator.free(self.vm_input);
                self.allocator.free(self.trace_merkle);
                self.allocator.free(self.fri_leaf);
                self.allocator.free(self.fri_node);
                self.allocator.free(self.fri_anchor);
                self.allocator.free(self.control);
                self.* = undefined;
            }
        };

        pub const ScheduleFacts = struct {
            sampled_value_count: u32,
            queried_values_per_query: u32,
            claimed_sum_count: u32,
            interaction_pow_bits: u32,
            pcs_pow_bits: u32,

            pub fn fromCaptured(captured: *const recursion.captured_fri.Owned) ScheduleFacts {
                return .{
                    .sampled_value_count = captured.sampled_value_count,
                    .queried_values_per_query = captured.queried_values_per_query,
                    .claimed_sum_count = captured.claimed_sum_count,
                    .interaction_pow_bits = captured.interaction_pow_bits,
                    .pcs_pow_bits = captured.pcs_pow_bits,
                };
            }
        };

        pub fn scheduleShape(
            circuit: *const circuit_mod.Circuit,
            trace_tree_heights: []const u32,
            facts: ScheduleFacts,
        ) !schedule.ScheduleShape {
            if (trace_tree_heights.len != recursion.fixed_profile.TREE_COUNT or
                circuit.fold_widths.len == 0 or
                !std.math.isPowerOfTwo(circuit.fold_widths[0]))
            {
                return error.AuthorityMismatch;
            }
            var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
            @memcpy(tree_heights[0..], trace_tree_heights);
            return recursion.transcript_shape.derive(
                circuit.profile(),
                tree_heights,
                .{
                    .sampled_value_count = facts.sampled_value_count,
                    .queried_values_per_query = facts.queried_values_per_query,
                    .claimed_sum_count = facts.claimed_sum_count,
                    .interaction_pow_bits = facts.interaction_pow_bits,
                    .pcs_pow_bits = facts.pcs_pow_bits,
                },
            ) catch return error.AuthorityMismatch;
        }

        pub fn validatePcsProfile(
            fri_circuit: *const circuit_mod.Circuit,
            pcs_circuit: *const pcs_circuit_mod.Circuit,
            column_log_sizes: []const []const u32,
        ) !void {
            const profile = pcs_circuit.profile();
            if (profile.lifting_log_size != fri_circuit.lifting_log_size or
                profile.log_blowup_factor != fri_circuit.log_blowup_factor or
                profile.query_count != fri_circuit.query_count or
                profile.trees.len != column_log_sizes.len)
            {
                return error.AuthorityMismatch;
            }
            for (profile.trees, column_log_sizes) |tree, expected_logs| {
                if (!std.mem.eql(u32, tree.column_log_sizes, expected_logs))
                    return error.AuthorityMismatch;
            }
        }

        pub const VmAirAuthority = struct {
            prepared: *const recursion.vm_air_composition_circuit.Prepared,
            definition: vm_input_air.Definition,
            relation: VmInputRelation.Plan,
            executor: vm_input_witness.Executor,

            pub fn init(
                allocator: std.mem.Allocator,
                prepared: *const recursion.vm_air_composition_circuit.Prepared,
            ) !VmAirAuthority {
                try prepared.validate();
                var definition = try vm_input_air.build(allocator);
                errdefer definition.deinit();
                const relation_plan = try VmInputRelation.authenticate(&definition);
                const binding_value = try vm_input_witness.Binding.canonical(&definition);
                const executor = try vm_input_witness.Executor.init(
                    &definition,
                    &binding_value,
                );
                return .{
                    .prepared = prepared,
                    .definition = definition,
                    .relation = relation_plan,
                    .executor = executor,
                };
            }

            pub fn deinit(self: *VmAirAuthority) void {
                self.definition.deinit();
                self.* = undefined;
            }
        };

        /// Move-safe admission token for the segment-leaf source cohort.
        ///
        /// `SegmentLeafOuterBundle.init` remains the hostile-boundary validator.  The
        /// token only removes duplicate top-level validation after that admission; it
        /// is deliberately not a substitute for the mutation-sensitive validators in
        /// each source writer.  In particular, every tree fill still replays the
        /// statement witness and validates the transcript/public prepared objects,
        /// and every destination boundary still authenticates the current manifest.
        pub const SegmentLeafAdmission = struct {
            const BorrowedAddresses = struct {
                transcript_preprocessing: usize,
                transcript_prepared: usize,
                leaf_preprocessing: usize,
                leaf: usize,
                public_data: usize,
                statement_authority: usize,
                statement_workspace: usize,
                statement_prepared: usize,
                public_source: usize,
                public_prepared: usize,
            };

            vm_schedule_digest: [8]u32,
            recursion_schedule_digest: [8]u32,
            manifest_seal: [32]u8,
            borrowed: BorrowedAddresses,

            pub fn issue(
                vm_plan: *const schedule.Plan,
                recursion_plan: *const schedule.Plan,
                inputs: SegmentTranscriptInputs,
                manifest: *const manifest_mod.Manifest,
            ) SegmentLeafAdmission {
                return .{
                    .vm_schedule_digest = vm_plan.authority_digest,
                    .recursion_schedule_digest = recursion_plan.authority_digest,
                    .manifest_seal = manifest.seal,
                    .borrowed = borrowedAddresses(inputs),
                };
            }

            /// Cheap identity check before a hot source operation.  Copied seals catch
            /// authority substitution, while the source-owned validators below this
            /// boundary continue to detect in-place mutation of every borrowed object.
            pub fn validateFor(
                self: SegmentLeafAdmission,
                vm_plan: *const schedule.Plan,
                recursion_plan: *const schedule.Plan,
                inputs: SegmentTranscriptInputs,
                manifest: *const manifest_mod.Manifest,
            ) !void {
                if (!std.meta.eql(self.vm_schedule_digest, vm_plan.authority_digest) or
                    !std.meta.eql(
                        self.recursion_schedule_digest,
                        recursion_plan.authority_digest,
                    ) or
                    !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
                    !std.meta.eql(self.borrowed, borrowedAddresses(inputs)))
                {
                    return error.AuthorityMismatch;
                }
            }

            fn borrowedAddresses(inputs: SegmentTranscriptInputs) BorrowedAddresses {
                return .{
                    .transcript_preprocessing = @intFromPtr(inputs.preprocessing),
                    .transcript_prepared = @intFromPtr(inputs.prepared),
                    .leaf_preprocessing = @intFromPtr(inputs.public.leaf_preprocessing),
                    .leaf = @intFromPtr(inputs.public.leaf),
                    .public_data = @intFromPtr(inputs.public.data),
                    .statement_authority = @intFromPtr(inputs.statement.authority),
                    .statement_workspace = @intFromPtr(inputs.statement.workspace),
                    .statement_prepared = @intFromPtr(inputs.statement.prepared),
                    .public_source = @intFromPtr(inputs.public.source),
                    .public_prepared = @intFromPtr(inputs.public.prepared),
                };
            }
        };

        pub const Authority = struct {
            allocator: std.mem.Allocator,
            circuit: *const circuit_mod.Circuit,
            pcs_circuit: *const pcs_circuit_mod.Circuit,
            query_mapping_reference: query_mapping_witness.Reference,
            query_bits_reference: query_bits_witness.Reference,
            query_mapping_preprocessing: query_mapping_witness.Preprocessed,
            query_bits_preprocessing: query_bits_witness.Preprocessed,
            merkle_root_reference: merkle_root_witness.Reference,
            merkle_root_preprocessing: merkle_root_witness.Preprocessed,
            trace_tree_profiles: []trace_merkle_witness.TreeProfile,
            trace_merkle_reference: trace_merkle_witness.Reference,
            trace_merkle_preprocessing: trace_merkle_witness.Preprocessed,
            fri_layer_profiles: []fri_leaf_witness.LayerProfile,
            fri_reference: fri_leaf_witness.Reference,
            fri_leaf_preprocessing: fri_leaf_witness.Preprocessed,
            fri_node_preprocessing: fri_node_witness.Preprocessed,
            fri_anchor_preprocessing: fri_anchor_witness.Preprocessed,
            vm_schedule: *schedule.Plan,
            recursion_schedule: *schedule.Plan,
            composition_control_preprocessing: composition_control_witness.CompositionPreprocessed,
            control_reference: control_witness.Reference,
            control_preprocessing: control_witness.Preprocessed,
            pcs_reference: pcs_witness.Reference,
            pcs_preprocessing: pcs_witness.Preprocessed,
            reference: input_witness.Reference,
            input_preprocessing: input_witness.Preprocessed,
            arithmetic_lanes: []lowering.Lane,
            arithmetic_reference: lowering.Reference,
            lowering_plan: lowering.Plan,
            vm_air: ?VmAirAuthority,
            public_native_sum_lane: ?lowering.Lane,
            segment_transcript_inputs: ?SegmentTranscriptInputs,
            segment_transcript: ?SegmentTranscriptSource,
            segment_leaf_admission: ?SegmentLeafAdmission,

            composition_control_definition: composition_control_air.Definition,
            query_bits_definition: query_bits_air.Definition,
            query_mapping_definition: query_mapping_air.Definition,
            merkle_root_definition: merkle_root_air.Definition,
            trace_merkle_definition: trace_merkle_air.Definition,
            fri_leaf_definition: fri_leaf_air.Definition,
            fri_node_definition: fri_node_air.Definition,
            fri_anchor_definition: fri_anchor_air.Definition,
            control_definition: control_air.Definition,
            pcs_definition: pcs_air.Definition,
            input_definition: input_air.Definition,
            multiply_definition: multiply_air.Definition,
            inverse_definition: inverse_air.Definition,
            linear_definition: linear_air.Definition,
            merkle_path_definition: merkle_path_air.Definition,
            composition_control_relation: CompositionControlRelation.Plan,
            query_bits_relation: QueryBitsRelation.Plan,
            query_mapping_relation: QueryMappingRelation.Plan,
            merkle_root_relation: MerkleRootRelation.Plan,
            trace_merkle_relation: TraceMerkleRelation.Plan,
            fri_leaf_relation: FriLeafRelation.Plan,
            fri_node_relation: FriNodeRelation.Plan,
            fri_anchor_relation: FriAnchorRelation.Plan,
            control_relation: ControlRelation.Plan,
            pcs_relation: PcsRelation.Plan,
            input_relation: InputRelation.Plan,
            multiply_relation: MultiplyRelation.Plan,
            inverse_relation: InverseRelation.Plan,
            linear_relation: LinearRelation.Plan,
            merkle_path_relation: MerklePathRelation.Plan,
            query_bits_executor: query_bits_witness.Executor,
            query_mapping_executor: query_mapping_witness.Executor,
            merkle_root_executor: merkle_root_witness.Executor,
            trace_merkle_executor: trace_merkle_witness.Executor,
            fri_leaf_executor: fri_leaf_witness.Executor,
            fri_node_executor: fri_node_witness.Executor,
            fri_anchor_executor: fri_anchor_witness.Executor,
            control_executor: control_witness.Executor,
            pcs_executor: pcs_witness.Executor,
            input_executor: input_witness.Executor,
            multiply_executor: multiply_witness.Executor,
            inverse_executor: inverse_witness.Executor,
            linear_executor: linear_witness.Executor,
            merkle_path_executor: merkle_path_witness.Executor,
            poseidon2_program: poseidon2_authority.Authority,
            poseidon2_row_count: u32,

            manifest: manifest_mod.Manifest,
            full_roster: bool,
            log_sizes: [LogIndex.count]u32,

            pub fn init(
                allocator: std.mem.Allocator,
                circuit: *const circuit_mod.Circuit,
                pcs_circuit: *const pcs_circuit_mod.Circuit,
                trace_tree_heights: []const u32,
                column_log_sizes: []const []const u32,
                schedule_facts: ScheduleFacts,
                vm_air_prepared: ?*const recursion.vm_air_composition_circuit.Prepared,
                verifier_plans: ?VerifierPlans,
                segment_transcript_inputs: ?SegmentTranscriptInputs,
                public_native_sum_lane: ?lowering.Lane,
                authenticated_poseidon_prefix_count: usize,
            ) !Authority {
                return initAuthority(
                    allocator,
                    circuit,
                    pcs_circuit,
                    trace_tree_heights,
                    column_log_sizes,
                    schedule_facts,
                    vm_air_prepared,
                    verifier_plans,
                    segment_transcript_inputs,
                    public_native_sum_lane,
                    authenticated_poseidon_prefix_count,
                );
            }

            pub fn deinit(self: *Authority) void {
                if (self.segment_transcript) |*source| source.deinit();
                if (self.vm_air) |*authority| authority.deinit();
                self.poseidon2_program.deinit();
                self.merkle_path_definition.deinit();
                self.linear_definition.deinit();
                self.inverse_definition.deinit();
                self.multiply_definition.deinit();
                self.input_definition.deinit();
                self.pcs_definition.deinit();
                self.control_definition.deinit();
                self.fri_anchor_definition.deinit();
                self.fri_node_definition.deinit();
                self.fri_leaf_definition.deinit();
                self.trace_merkle_definition.deinit();
                self.merkle_root_definition.deinit();
                self.query_mapping_definition.deinit();
                self.query_bits_definition.deinit();
                self.composition_control_definition.deinit();
                self.lowering_plan.deinit();
                self.allocator.free(self.arithmetic_lanes);
                self.input_preprocessing.deinit();
                self.pcs_preprocessing.deinit();
                self.control_preprocessing.deinit();
                self.fri_anchor_preprocessing.deinit();
                self.fri_node_preprocessing.deinit();
                self.fri_leaf_preprocessing.deinit();
                self.trace_merkle_preprocessing.deinit();
                self.allocator.free(self.trace_tree_profiles);
                self.merkle_root_preprocessing.deinit();
                self.query_bits_preprocessing.deinit();
                self.query_mapping_preprocessing.deinit();
                self.composition_control_preprocessing.deinit();
                self.recursion_schedule.deinit();
                self.allocator.destroy(self.recursion_schedule);
                self.vm_schedule.deinit();
                self.allocator.destroy(self.vm_schedule);
                self.allocator.free(self.fri_layer_profiles);
                self.* = undefined;
            }

            fn geometry(self: *const Authority) [4]u32 {
                return .{
                    self.manifest.total_preprocessed_columns,
                    self.manifest.total_main_columns,
                    self.manifest.total_interaction_columns,
                    self.manifest.total_constraints,
                };
            }
        };
    };
}
