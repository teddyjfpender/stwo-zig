//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const circuit_mod = context.d_circuit_mod;
        const pcs_circuit_mod = context.d_pcs_circuit_mod;
        const pcs_witness = context.d_pcs_witness;
        const schedule = context.d_schedule;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const manifest_mod = context.d_manifest_mod;
        const manifest_v2 = context.d_manifest_v2;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const framework = context.d_framework;
        const shared_schedule_v2 = context.d_shared_schedule_v2;
        const public_native_sum = context.d_public_native_sum;
        const LogIndex = context.d_LogIndex;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
        const PCS_SEGMENT_CIRCUIT_ID = context.d_PCS_SEGMENT_CIRCUIT_ID;
        const PCS_LEFT_CIRCUIT_ID = context.d_PCS_LEFT_CIRCUIT_ID;
        const PCS_RIGHT_CIRCUIT_ID = context.d_PCS_RIGHT_CIRCUIT_ID;
        const NATIVE_V2_CORE_FORMAT_VERSION = context.d_NATIVE_V2_CORE_FORMAT_VERSION;
        const NATIVE_V2_CORE_FIRST_ROW = context.d_NATIVE_V2_CORE_FIRST_ROW;
        const NATIVE_V2_CORE_LAST_ROW = context.d_NATIVE_V2_CORE_LAST_ROW;
        const NATIVE_V2_CORE_ROW_COUNT = context.d_NATIVE_V2_CORE_ROW_COUNT;
        const NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT = context.d_NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT;
        const NATIVE_V2_CORE_RETAINS_SELF_POINTERS = context.d_NATIVE_V2_CORE_RETAINS_SELF_POINTERS;
        const NATIVE_V2_CORE_AUTHORITY_TRANSCRIPT_DOMAIN = context.d_NATIVE_V2_CORE_AUTHORITY_TRANSCRIPT_DOMAIN;
        const NativeSegmentCoreAuthorityInputsV2 = context.d_NativeSegmentCoreAuthorityInputsV2;
        const NativeSegmentCoreAuthorityInputsV4 = context.d_NativeSegmentCoreAuthorityInputsV4;
        const NativeSegmentCoreGeneratedV2 = context.d_NativeSegmentCoreGeneratedV2;
        const NativeSegmentCoreComponentsV2 = context.d_NativeSegmentCoreComponentsV2;
        const initNativeSegmentCoreComponents = context.d_initNativeSegmentCoreComponents;
        const validateMaterializedArithmeticLane = context.d_validateMaterializedArithmeticLane;
        const nativeV2CoreStageFailure = context.d_nativeV2CoreStageFailure;
        const appendNativeSegmentCoreTupleContributions = context.d_appendNativeSegmentCoreTupleContributions;
        const VerifierPlans = context.d_VerifierPlans;
        const PreparedQueryWitness = context.d_PreparedQueryWitness;
        const TupleLedger = context.d_TupleLedger;
        const ClosureAudit = context.d_ClosureAudit;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const ScheduleFacts = context.d_ScheduleFacts;
        const Authority = context.d_Authority;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const PoseidonCallBuffers = context.d_PoseidonCallBuffers;
        const buildArithmeticEvaluations = context.d_buildArithmeticEvaluations;
        const Components = context.d_Components;
        const fillPreprocessed = context.d_fillPreprocessed;
        const fillMainConsumers = context.d_fillMainConsumers;
        const fillPoseidonMain = context.d_fillPoseidonMain;
        const fillInteraction = context.d_fillInteraction;
        const fillInteractionWithGenerator = context.d_fillInteractionWithGenerator;
        const fillNativeInteraction = context.d_fillNativeInteraction;
        const fillNativeInteractionWithGenerator = context.d_fillNativeInteractionWithGenerator;
        const NativeInteractionClaims = context.d_NativeInteractionClaims;
        const mixAuthority = context.d_mixAuthority;
        const nativeCoreClaims = context.d_nativeCoreClaims;
        const nativeCoreAuthorityIdentity = context.d_nativeCoreAuthorityIdentity;
        const loweringLaneEql = context.d_loweringLaneEql;
        const nativeCoreGeneratedIdentity = context.d_nativeCoreGeneratedIdentity;
        const publishNativeCoreTree = context.d_publishNativeCoreTree;
        const digestWords = context.d_digestWords;
        const TreeStorage = context.d_TreeStorage;

        pub const NativeSegmentCoreV2 = struct {
            pub const AuthorityInputs = NativeSegmentCoreAuthorityInputsV2;
            pub const GeneratedInteractionsV2 = NativeSegmentCoreGeneratedV2;
            pub const Components = NativeSegmentCoreComponentsV2;

            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            vm_air_prepared: recursion.vm_composition_preparation.Source,
            verifier_plans: VerifierPlans,
            public_native_sum_lane: lowering.Lane,
            public_native_sum_evaluation: lowering.Evaluation,
            public_native_sum_authority_id: [32]u8,
            public_native_sum_evaluation_id: [32]u8,
            authority: Authority,
            inactive: circuit_mod.Evaluation,
            pcs_inactive: pcs_circuit_mod.Evaluation,
            prepared_query: PreparedQueryWitness,
            pcs_active_inputs: []M31,
            pcs_inactive_inputs: []M31,
            invocations: InvocationBuffers,
            merkle_paths: MerklePathBuffers,
            poseidon_calls: PoseidonCallBuffers,
            prepared_relation_rows: PreparedRelationRows,
            preprocessed_tree: TreeStorage,
            main_tree: TreeStorage,
            interaction_tree: TreeStorage,
            boundary_prefix_count: usize,
            core_poseidon_call_count: usize,
            complete_layout: shared_schedule_v2.SharedPoseidonCallLayoutV2,
            provider_main_ready: bool,
            generated_interactions: ?NativeSegmentCoreGeneratedV2,
            authority_id: [32]u8,
            prepared_inputs_v4: ?*PreparedInputsV4 = null,

            pub const SourceIdentitiesV4 = struct { fri: [32]u8, pcs: [32]u8, vm: [32]u8 };

            /// Admitted input projection copied from the finalized Tree1 and
            /// independently owned roots. No capture graph/evaluation alias
            /// escapes this owner. Legacy constructors retain their full checks.
            const PreparedInputsV4 = opaque {
                const Storage = struct {
                    allocator: std.mem.Allocator,
                    input_values: []M31,
                    trace_roots: []recursion.protocol.Digest,
                    fri_roots: []recursion.protocol.Digest,
                    pcs_graph_digest: [32]u8,
                    identities: SourceIdentitiesV4,
                    calls: PoseidonCallBuffers,
                    layout: shared_schedule_v2.SharedPoseidonCallLayoutV2,
                };

                fn admit(core: *NativeSegmentCoreV2) !*PreparedInputsV4 {
                    try core.validateCoreReady();
                    if (std.meta.activeTag(core.vm_air_prepared) != .immutable) return error.AuthorityMismatch;
                    const allocator = core.allocator;
                    const slot = core.authority.manifest.placements[@intFromEnum(manifest_mod.ComponentKey.fri_verifier_input)] orelse return error.V2CoreCohortMismatch;
                    const values = core.main_tree.columns[slot.main_offset + @intFromEnum(input_witness.MainSource.value)];
                    const count = core.authority.input_preprocessing.rows.len;
                    if (count > values.len) return error.V2CoreCohortMismatch;
                    return takeAdmitted(allocator, values, count, slot.geometry.log_size, core.captured.trace_roots, core.captured.fri_roots, core.captured.pcs_circuit.graph().identity_digest, core.sourceIdentities(), core.complete_layout, &core.poseidon_calls);
                }

                // The caller has admitted the complete source/layout. All
                // fallible allocation precedes the actual buffer ownership move.
                fn takeAdmitted(allocator: std.mem.Allocator, committed_values: []const M31, logical_count: usize, log_size: u32, trace_source: []const recursion.protocol.Digest, fri_source: []const recursion.protocol.Digest, pcs_graph_digest: [32]u8, identities: SourceIdentitiesV4, layout: shared_schedule_v2.SharedPoseidonCallLayoutV2, calls: *PoseidonCallBuffers) !*PreparedInputsV4 {
                    if (log_size >= @bitSizeOf(usize) or logical_count > committed_values.len or
                        committed_values.len != (@as(usize, 1) << @intCast(log_size))) return error.V2CoreCohortMismatch;
                    const input_values = try allocator.alloc(M31, logical_count);
                    errdefer allocator.free(input_values);
                    // Tree1 is in committed circle order; all row consumers and
                    // cold-source comparisons index preprocessing in logical order.
                    for (input_values, 0..) |*value, logical_row|
                        value.* = committed_values[framework.committedRow(logical_row, log_size)];
                    const trace = try allocator.dupe(recursion.protocol.Digest, trace_source);
                    errdefer allocator.free(trace);
                    const fri = try allocator.dupe(recursion.protocol.Digest, fri_source);
                    errdefer allocator.free(fri);
                    const owned = try allocator.create(Storage);
                    owned.* = .{ .allocator = allocator, .input_values = input_values, .trace_roots = trace, .fri_roots = fri, .pcs_graph_digest = pcs_graph_digest, .identities = identities, .calls = calls.*, .layout = layout };
                    calls.* = .{ .allocator = calls.allocator, .calls = &.{}, .outputs = &.{}, .cursor = 0, .outputs_ready = false };
                    return @ptrCast(owned);
                }

                fn view(self: *const PreparedInputsV4) *const Storage {
                    return @ptrCast(@alignCast(self));
                }

                fn validateSource(self: *const PreparedInputsV4, core: *const NativeSegmentCoreV2) !void {
                    const owned = self.view();
                    const expected: SourceIdentitiesV4 = .{ .fri = core.captured.circuit.identity_digest, .pcs = core.captured.pcs_circuit.view().identity_digest, .vm = core.vm_air_prepared.view().circuit.identity_digest };
                    if (!std.meta.eql(expected, owned.identities) or
                        !std.mem.eql(recursion.protocol.Digest, core.captured.trace_roots, owned.trace_roots) or
                        !std.mem.eql(recursion.protocol.Digest, core.captured.fri_roots, owned.fri_roots) or
                        !std.meta.eql(core.captured.pcs_circuit.graph().identity_digest, owned.pcs_graph_digest)) return error.V2CoreCohortMismatch;
                    const source_evaluations = core.evaluations();
                    for (core.authority.input_preprocessing.rows, owned.input_values) |row, value| {
                        const expected_value = try source_evaluations.at(row.lane).values[row.node_id].tryIntoM31();
                        if (!expected_value.eql(value)) return error.V2CoreCohortMismatch;
                    }
                }

                fn deinit(self: *PreparedInputsV4) void {
                    const owned: *Storage = @ptrCast(@alignCast(self));
                    const allocator = owned.allocator;
                    owned.calls.deinit();
                    allocator.free(owned.input_values);
                    allocator.free(owned.fri_roots);
                    allocator.free(owned.trace_roots);
                    allocator.destroy(owned);
                }
            };

            fn poseidonBuffers(self: *const NativeSegmentCoreV2) *const PoseidonCallBuffers {
                if (self.prepared_inputs_v4) |owned| return &owned.view().calls;
                return &self.poseidon_calls;
            }

            fn poseidonBuffersMut(self: *NativeSegmentCoreV2) *PoseidonCallBuffers {
                if (self.prepared_inputs_v4) |owned| {
                    const backing: *PreparedInputsV4.Storage = @ptrCast(@alignCast(owned));
                    return &backing.calls;
                }
                return &self.poseidon_calls;
            }

            pub fn poseidonCallCount(self: *const NativeSegmentCoreV2) usize {
                return self.poseidonBuffers().calls.len;
            }

            pub fn appendPoseidonTupleContributions(self: *const NativeSegmentCoreV2, ledger: *TupleLedger, domain_mask: u64) !void {
                try self.validatePreparedComplete();
                return context.d_appendNativePoseidonProviderTuples(self.poseidonBuffers(), ledger, domain_mask);
            }

            pub fn sourceIdentities(self: *const NativeSegmentCoreV2) SourceIdentitiesV4 {
                if (self.prepared_inputs_v4) |owned| return owned.view().identities;
                return .{ .fri = self.captured.circuit.identity_digest, .pcs = self.captured.pcs_circuit.view().identity_digest, .vm = self.vm_air_prepared.view().circuit.identity_digest };
            }

            pub fn preparedInputValue(self: *const NativeSegmentCoreV2, row_index: usize) !M31 {
                if (self.prepared_inputs_v4) |owned| return owned.view().input_values[row_index];
                const row = self.authority.input_preprocessing.rows[row_index];
                return self.evaluations().at(row.lane).values[row.node_id].tryIntoM31();
            }

            pub fn preparedRootWitness(self: *const NativeSegmentCoreV2) context.d_merkle_root_witness.RootWitness {
                if (self.prepared_inputs_v4) |owned| return .{ .segment_leaf = .{ .trace = owned.view().trace_roots, .fri = owned.view().fri_roots } };
                return self.captured.merkleRootWitness();
            }

            pub fn preparedInputRetainedBytes(self: *const NativeSegmentCoreV2) usize {
                const owned = (self.prepared_inputs_v4 orelse return 0).view();
                return @sizeOf(PreparedInputsV4.Storage) + owned.input_values.len * @sizeOf(M31) +
                    (owned.trace_roots.len + owned.fri_roots.len) * @sizeOf(recursion.protocol.Digest);
            }

            pub const testing = if (@import("builtin").is_test) struct {
                pub fn exerciseProjectionOwnership(allocator: std.mem.Allocator) !void {
                    var calls = try PoseidonCallBuffers.init(allocator, 3);
                    defer calls.deinit();
                    for (calls.calls) |*call| call.* = .{ .input = @splat(0), .wide = false, .io = true, .narrow_output = null };
                    calls.cursor = calls.calls.len;
                    const call_address = @intFromPtr(calls.calls.ptr);
                    const output_address = @intFromPtr(calls.outputs.ptr);
                    const layout = try shared_schedule_v2.SharedPoseidonCallLayoutV2.initComplete(1, 1, 1, calls.calls);
                    const logical_inputs = [_]M31{ M31.fromCanonical(11), M31.fromCanonical(23), M31.fromCanonical(37), M31.fromCanonical(41), M31.fromCanonical(59), M31.fromCanonical(67), M31.fromCanonical(79) };
                    var input_columns = try context.d_ColumnBuffer(1).init(allocator, 4);
                    defer input_columns.deinit();
                    @memset(input_columns.views[0], M31.zero());
                    @memcpy(input_columns.views[0][0..logical_inputs.len], &logical_inputs);
                    var committed_inputs: [16]M31 = undefined;
                    var committed_evaluations = [_]context.d_prover_pcs.ColumnEvaluation{.{ .log_size = 4, .values = &committed_inputs }};
                    // Borrowed test destination: scatter uses the same production
                    // writer as Native Tree1, including permutation and padding.
                    var tree = TreeStorage{ .allocator = allocator, .evaluations = &committed_evaluations, .columns = &.{}, .storage = &committed_inputs, .backing = &.{} };
                    input_columns.scatter(&tree, 0);
                    try std.testing.expect(!std.meta.eql(logical_inputs, committed_inputs[0..logical_inputs.len].*));
                    var roots = [_]recursion.protocol.Digest{@splat(1)};
                    const id: [32]u8 = @splat(7);
                    const owned = try PreparedInputsV4.takeAdmitted(allocator, &committed_inputs, logical_inputs.len, 4, &roots, &roots, id, .{ .fri = id, .pcs = id, .vm = id }, layout, &calls);
                    defer owned.deinit();
                    try std.testing.expectEqual(@as(usize, 0), calls.calls.len);
                    try std.testing.expectEqual(@as(usize, 0), calls.outputs.len);
                    try std.testing.expectEqual(call_address, @intFromPtr(owned.view().calls.calls.ptr));
                    try std.testing.expectEqual(output_address, @intFromPtr(owned.view().calls.outputs.ptr));
                    try std.testing.expectEqualSlices(M31, &logical_inputs, owned.view().input_values);
                    @memset(&committed_inputs, M31.zero());
                    @memset(input_columns.views[0], M31.zero());
                    roots[0][0] = 2;
                    try std.testing.expectEqualSlices(M31, &logical_inputs, owned.view().input_values);
                    try std.testing.expectEqual(@as(u32, 1), owned.view().trace_roots[0][0]);
                    try std.testing.expectEqual(@as(u32, 1), owned.view().fri_roots[0][0]);
                    try owned.view().layout.validate(owned.view().calls.calls);
                }

                pub const Receipt = struct { legacy_ns: u64, native_ns: u64, retained_input_bytes: usize, tree2_sha256: [32]u8 };

                fn treeDigest(core: *const NativeSegmentCoreV2) [32]u8 {
                    var hash = std.crypto.hash.sha2.Sha256.init(.{});
                    hash.update(std.mem.sliceAsBytes(core.interaction_tree.storage));
                    return hash.finalResult();
                }

                fn expectColdRejection(core: *const NativeSegmentCoreV2) !void {
                    if (core.validateCoreReady()) |_| return error.NativePreparedSourceMutationAccepted else |err| switch (err) {
                        error.InvalidWitness, error.UnsatisfiedCircuit, error.V2CoreCohortMismatch => {},
                        else => return err,
                    }
                }

                /// Diagnostic only: one retained core, one Tree2 buffer. No PCS,
                /// native reproving, second Tree2 allocation, or producer hook.
                pub fn exercisePreparedRegression(core: *NativeSegmentCoreV2, allocator: std.mem.Allocator, relations: *const universal.UniversalRelations, providers: *const shared_provider.SharedProviderRelations) !Receipt {
                    const owned = core.prepared_inputs_v4 orelse return error.NativePreparedProjectionRequired;
                    try core.validateComplete();
                    if (core.generated_interactions != null) return error.NativePreparedRegressionRequiresCleanTree;
                    defer {
                        @memset(core.interaction_tree.storage, M31.zero());
                        core.generated_interactions = null;
                    }
                    var legacy_audit = ClosureAudit.init(allocator, false);
                    defer legacy_audit.deinit();
                    var arithmetic_storage: [MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation = undefined;
                    var timer = try std.time.Timer.start();
                    const legacy = try fillInteraction(allocator, &core.authority, &core.interaction_tree, core.evaluations(), core.pcsInputs(), try buildArithmeticEvaluations(&core.authority, core.captured, &core.inactive, core.public_native_sum_evaluation, &arithmetic_storage), &core.invocations, core.prepared_query.value, core.captured.merkleRootWitness(), &core.merkle_paths, core.poseidonBuffers(), &core.prepared_relation_rows, providers, relations, &legacy_audit);
                    const legacy_ns = timer.read();
                    const expected_digest = treeDigest(core);
                    @memset(core.interaction_tree.storage, M31.zero());

                    // Both externally mutable inputs are restored even if any
                    // check or generation fails. Operational inputs are private.
                    var selected: ?usize = null;
                    for (core.authority.input_preprocessing.rows, 0..) |row, i| if (row.lane == 0 and row.use_count != 0) {
                        selected = i;
                        break;
                    };
                    const row_index = selected orelse return error.NativePreparedInputFixtureRequired;
                    const source = core.authority.input_preprocessing.rows[row_index];
                    const previous_value = core.captured.evaluation.values[source.node_id];
                    defer core.captured.evaluation.values[source.node_id] = previous_value;
                    core.captured.evaluation.values[source.node_id] = previous_value.add(QM31.one());
                    try std.testing.expectError(error.V2CoreCohortMismatch, owned.validateSource(core));
                    try expectColdRejection(core);
                    try std.testing.expectEqualDeep(owned.view().input_values[row_index], try core.preparedInputValue(row_index));
                    if (core.captured.trace_roots.len == 0 or core.captured.digest_storage.len == 0 or
                        @intFromPtr(core.captured.trace_roots.ptr) != @intFromPtr(core.captured.digest_storage.ptr)) return error.NativePreparedRootFixtureRequired;
                    const previous_root = core.captured.digest_storage[0];
                    defer core.captured.digest_storage[0] = previous_root;
                    core.captured.digest_storage[0][0] = (previous_root[0] + 1) % @import("stwo_core").fields.m31.Modulus;
                    try std.testing.expectError(error.V2CoreCohortMismatch, owned.validateSource(core));
                    core.captured.evaluation.values[source.node_id] = previous_value;
                    try expectColdRejection(core); // The changed root alone is rejected.
                    core.captured.evaluation.values[source.node_id] = previous_value.add(QM31.one());
                    try std.testing.expectEqualDeep(previous_root, core.preparedRootWitness().segment_leaf.trace[0]);
                    const before_fri = circuit_mod.Circuit.testing.snapshot();
                    const before_pcs = pcs_circuit_mod.Circuit.testing.snapshot();
                    for (0..3) |_| {
                        try core.validatePreparedComplete();
                        _ = try core.completeScheduleReceipt();
                        _ = try core.completePoseidonCalls();
                        _ = core.poseidonCallCount();
                    }
                    var native_audit = ClosureAudit.init(allocator, false);
                    defer native_audit.deinit();
                    timer.reset();
                    const native = try fillNativeInteraction(allocator, &core.authority, &core.interaction_tree, owned.view().input_values, core.pcsInputs(), &core.invocations, core.prepared_query.value, core.preparedRootWitness(), &core.merkle_paths, core.poseidonBuffers(), &core.prepared_relation_rows, providers, relations, &native_audit);
                    const native_ns = timer.read();
                    try std.testing.expectEqualDeep(before_fri, circuit_mod.Circuit.testing.snapshot());
                    try std.testing.expectEqualDeep(before_pcs, pcs_circuit_mod.Circuit.testing.snapshot());
                    try std.testing.expectEqualDeep(nativeCoreClaims(legacy), native.claims);
                    try std.testing.expectEqualDeep(legacy.poseidon2, native.poseidon2_partials);
                    try std.testing.expectEqualDeep(legacy.public_boundaries, native.public_boundaries);
                    try std.testing.expectEqualDeep(legacy_audit.rows, native_audit.rows);
                    try std.testing.expectEqualDeep(legacy_audit.public_boundaries, native_audit.public_boundaries);
                    try std.testing.expectEqualDeep(expected_digest, treeDigest(core));

                    // Retain an actual active row's recursion-wire pole check.
                    // The removed legacy diagnostic never substitutes for it.
                    var pole = relations.*;
                    const domain: usize = @intFromEnum(context.d_RelationDomain.recursion_wire);
                    pole.elements[domain] = universal.Elements.init(pole.elements[domain].arity, QM31.fromBase(M31.fromCanonical(source.circuit_id)), QM31.zero());
                    const logical = input_witness.logicalInputs((input_witness.MainRow{ .enabler = M31.one(), .value = owned.view().input_values[row_index] }).values(), source.values(), .segment_leaf);
                    if (context.d_InputFramework.generatePrepared(allocator, &core.authority.input_relation, &.{logical}, 1, &pole)) |generated| {
                        var unexpected = generated;
                        unexpected.deinit(allocator);
                        return error.NativePreparedPoleAccepted;
                    } else |err| if (err != error.ZeroDenominator) return err;
                    return .{ .legacy_ns = legacy_ns, .native_ns = native_ns, .retained_input_bytes = core.preparedInputRetainedBytes(), .tree2_sha256 = expected_digest };
                }
            } else struct {};

            pub fn init(
                allocator: std.mem.Allocator,
                inputs: AuthorityInputs,
            ) !NativeSegmentCoreV2 {
                inputs.validate() catch |err|
                    return nativeV2CoreStageFailure("inputs", err);
                return initAuthenticated(
                    allocator,
                    inputs.captured,
                    inputs.vm_air,
                    inputs.verifier_plans,
                    inputs.public_native_sum_source.loweringLane(),
                    try inputs.public_native_sum_evaluation.loweringEvaluation(
                        inputs.public_native_sum_source,
                    ),
                    inputs.public_native_sum_evaluation.identity,
                    null,
                    .{ .legacy = .{
                        .prepared = inputs.transcript_prepared,
                        .program = inputs.transcript_program,
                        .execution = inputs.transcript_execution,
                        .plan = inputs.transcript_plan,
                    } },
                    inputs.boundary_layout,
                    inputs.boundary_calls,
                    null,
                );
            }

            /// Versioned sibling for a native capture whose public arithmetic
            /// graph and complete q193 query words are authenticated by newer
            /// typed owners.  The frozen SegmentV2 constructor above remains
            /// byte- and API-identical.
            pub fn initVersionedV4(
                allocator: std.mem.Allocator,
                inputs: NativeSegmentCoreAuthorityInputsV4,
            ) !NativeSegmentCoreV2 {
                inputs.validate() catch |err|
                    return nativeV2CoreStageFailure("versioned-inputs", err);
                return initAuthenticated(
                    allocator,
                    inputs.captured,
                    inputs.vm_air,
                    inputs.verifier_plans,
                    inputs.public_native_sum_lane,
                    inputs.public_native_sum_evaluation,
                    inputs.public_native_sum_evaluation_id,
                    inputs.statement_arithmetic,
                    .{ .full_words = inputs.full_query_words },
                    inputs.boundary_layout,
                    inputs.boundary_calls,
                    null,
                );
            }

            /// Target-native sibling for role-specific padding remints. The
            /// requested domains are consumed before any tree allocation, so
            /// every column is genuinely regenerated at the target.
            pub fn initVersionedV4ForLogSizes(
                allocator: std.mem.Allocator,
                inputs: NativeSegmentCoreAuthorityInputsV4,
                requested_log_sizes: [LogIndex.count]u32,
            ) !NativeSegmentCoreV2 {
                inputs.validate() catch |err|
                    return nativeV2CoreStageFailure("versioned-padded-inputs", err);
                return initAuthenticated(
                    allocator,
                    inputs.captured,
                    inputs.vm_air,
                    inputs.verifier_plans,
                    inputs.public_native_sum_lane,
                    inputs.public_native_sum_evaluation,
                    inputs.public_native_sum_evaluation_id,
                    inputs.statement_arithmetic,
                    .{ .full_words = inputs.full_query_words },
                    inputs.boundary_layout,
                    inputs.boundary_calls,
                    requested_log_sizes,
                );
            }

            const QueryAuthorityV4 = union(enum) {
                legacy: struct {
                    prepared: *const context.d_segment_transcript_source_v2.PreparedV2,
                    program: *const recursion.transcript_program_v2.Program,
                    execution: *const recursion.transcript_program_v2.Execution,
                    plan: *const schedule.Plan,
                },
                full_words: []const M31,
            };

            fn initAuthenticated(
                allocator: std.mem.Allocator,
                captured: *const recursion.captured_fri.Owned,
                vm_air: recursion.vm_composition_preparation.Source,
                verifier_plans: VerifierPlans,
                public_lane: lowering.Lane,
                public_evaluation: lowering.Evaluation,
                public_evaluation_id: [32]u8,
                statement_arithmetic: ?*const recursion.ethereum_statement_arithmetic_v4.Prepared,
                query_authority: QueryAuthorityV4,
                boundary_layout: *const shared_schedule_v2.SharedPoseidonCallLayoutV2,
                boundary_calls: []const shared_schedule_v2.Call,
                requested_log_sizes: ?[LogIndex.count]u32,
            ) !NativeSegmentCoreV2 {
                const boundary_prefix_count = boundary_calls.len;
                var authority = Authority.initWithStatementArithmetic(
                    allocator,
                    &captured.circuit,
                    &captured.pcs_circuit,
                    captured.trace_tree_heights,
                    captured.column_log_sizes,
                    ScheduleFacts.fromCaptured(captured),
                    vm_air,
                    verifier_plans,
                    null,
                    public_lane,
                    boundary_prefix_count,
                    requested_log_sizes,
                    statement_arithmetic,
                ) catch |err| return nativeV2CoreStageFailure("authority", err);
                errdefer authority.deinit();
                var inactive = try captured.evaluateInactive();
                errdefer inactive.deinit();
                var pcs_inactive = try captured.evaluatePcsInactive();
                errdefer pcs_inactive.deinit();
                var prepared_query = switch (query_authority) {
                    .legacy => |legacy| try PreparedQueryWitness.initV2(
                        allocator,
                        captured,
                        legacy.prepared,
                        legacy.program,
                        legacy.execution,
                        legacy.plan,
                    ),
                    .full_words => |words| try PreparedQueryWitness.initFullWordsV2(
                        allocator,
                        captured,
                        words,
                    ),
                };
                errdefer prepared_query.deinit();

                const pcs_input_count = captured.pcs_circuit.view().bindings.len;
                const pcs_active_inputs = try allocator.alloc(M31, pcs_input_count);
                errdefer allocator.free(pcs_active_inputs);
                const pcs_inactive_inputs = try allocator.alloc(M31, pcs_input_count);
                errdefer allocator.free(pcs_inactive_inputs);
                try captured.pcs_circuit.inputValuesInto(
                    &captured.pcs_evaluation,
                    pcs_active_inputs,
                );
                try captured.pcs_circuit.inputValuesInto(
                    &pcs_inactive,
                    pcs_inactive_inputs,
                );

                var invocations = try InvocationBuffers.init(
                    allocator,
                    authority.lowering_plan.counts(.segment_leaf),
                );
                errdefer invocations.deinit();
                var merkle_paths = try MerklePathBuffers.init(allocator, captured);
                errdefer merkle_paths.deinit();
                var poseidon_calls = try PoseidonCallBuffers.init(
                    allocator,
                    authority.poseidon2_row_count,
                );
                errdefer poseidon_calls.deinit();
                try poseidon_calls.appendAuthenticatedPrefix(boundary_calls);
                var prepared_relation_rows = try PreparedRelationRows.init(
                    allocator,
                    &authority,
                );
                errdefer prepared_relation_rows.deinit();
                var preprocessed_tree = try TreeStorage.init(
                    allocator,
                    &authority.manifest,
                    manifest_mod.PREPROCESSED_TREE_INDEX,
                );
                errdefer preprocessed_tree.deinit();
                var main_tree = try TreeStorage.init(
                    allocator,
                    &authority.manifest,
                    manifest_mod.MAIN_TREE_INDEX,
                );
                errdefer main_tree.deinit();
                var interaction_tree = try TreeStorage.init(
                    allocator,
                    &authority.manifest,
                    manifest_mod.INTERACTION_TREE_INDEX,
                );
                errdefer interaction_tree.deinit();

                var result = NativeSegmentCoreV2{
                    .allocator = allocator,
                    .captured = captured,
                    .vm_air_prepared = vm_air,
                    .verifier_plans = verifier_plans,
                    .public_native_sum_lane = public_lane,
                    .public_native_sum_evaluation = public_evaluation,
                    .public_native_sum_authority_id = public_lane.circuit_identity,
                    .public_native_sum_evaluation_id = public_evaluation_id,
                    .authority = authority,
                    .inactive = inactive,
                    .pcs_inactive = pcs_inactive,
                    .prepared_query = prepared_query,
                    .pcs_active_inputs = pcs_active_inputs,
                    .pcs_inactive_inputs = pcs_inactive_inputs,
                    .invocations = invocations,
                    .merkle_paths = merkle_paths,
                    .poseidon_calls = poseidon_calls,
                    .prepared_relation_rows = prepared_relation_rows,
                    .preprocessed_tree = preprocessed_tree,
                    .main_tree = main_tree,
                    .interaction_tree = interaction_tree,
                    .boundary_prefix_count = boundary_prefix_count,
                    .core_poseidon_call_count = 0,
                    .complete_layout = undefined,
                    .provider_main_ready = false,
                    .generated_interactions = null,
                    .authority_id = undefined,
                };
                result.prepareColdTreesAndCoreCalls(boundary_layout) catch |err|
                    return nativeV2CoreStageFailure("cold-trees-and-core-calls", err);
                if (std.meta.activeTag(query_authority) == .full_words and std.meta.activeTag(vm_air) == .immutable)
                    result.prepared_inputs_v4 = try PreparedInputsV4.admit(&result);
                return result;
            }

            /// Initializes an already stable owner slot. This is the preferred entry
            /// point for a heap-owned full SegmentV2 cohort; it also makes the storage
            /// policy explicit at the aggregation boundary. `init` remains available
            /// for standalone callers because this type has no retained self/sibling
            /// pointers (see `NATIVE_V2_CORE_RETAINS_SELF_POINTERS`).
            pub fn initInPlace(
                self: *NativeSegmentCoreV2,
                allocator: std.mem.Allocator,
                inputs: AuthorityInputs,
            ) !void {
                self.* = try init(allocator, inputs);
            }

            pub fn deinit(self: *NativeSegmentCoreV2) void {
                if (self.prepared_inputs_v4) |owned| owned.deinit();
                self.interaction_tree.deinit();
                self.main_tree.deinit();
                self.preprocessed_tree.deinit();
                self.prepared_relation_rows.deinit();
                self.poseidon_calls.deinit();
                self.merkle_paths.deinit();
                self.invocations.deinit();
                self.allocator.free(self.pcs_inactive_inputs);
                self.allocator.free(self.pcs_active_inputs);
                self.prepared_query.deinit();
                self.pcs_inactive.deinit();
                self.inactive.deinit();
                self.authority.deinit();
                self.* = undefined;
            }

            fn prepareColdTreesAndCoreCalls(
                self: *NativeSegmentCoreV2,
                boundary_layout: *const shared_schedule_v2.SharedPoseidonCallLayoutV2,
            ) !void {
                fillPreprocessed(&self.authority, &self.preprocessed_tree) catch |err|
                    return nativeV2CoreStageFailure("preprocessed", err);
                var arithmetic_storage: [MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation = undefined;
                const arithmetic_evaluations = try buildArithmeticEvaluations(
                    &self.authority,
                    self.captured,
                    &self.inactive,
                    self.public_native_sum_evaluation,
                    &arithmetic_storage,
                );
                self.authority.lowering_plan.materializeInto(
                    self.authority.arithmetic_reference,
                    arithmetic_evaluations,
                    .segment_leaf,
                    self.invocations.view(),
                ) catch |err| return nativeV2CoreStageFailure("arithmetic-materialize", err);
                validateMaterializedArithmeticLane(
                    self.authority.arithmetic_reference,
                    arithmetic_evaluations,
                    .segment_leaf,
                    self.invocations.view(),
                    public_native_sum.CIRCUIT_ID,
                ) catch |err| return nativeV2CoreStageFailure("arithmetic-replay", err);
                fillMainConsumers(
                    &self.authority,
                    &self.main_tree,
                    self.evaluations(),
                    self.pcsInputs(),
                    &self.invocations,
                    self.prepared_query.value,
                    self.captured.merkleRootWitness(),
                    self.captured.traceOpeningWitness(),
                    self.captured.friOpeningWitness(),
                    self.captured,
                    &self.merkle_paths,
                    self.poseidonBuffersMut(),
                    &self.prepared_relation_rows,
                ) catch |err| return nativeV2CoreStageFailure("main-consumers", err);
                const core_calls = try self.poseidonBuffers().preparedSuffix(
                    self.boundary_prefix_count,
                );
                if (core_calls.len == 0) return error.V2CoreCohortMismatch;
                self.core_poseidon_call_count = core_calls.len;
                self.complete_layout = shared_schedule_v2.SharedPoseidonCallLayoutV2
                    .initComplete(
                    try boundary_layout.transcript.count(),
                    try boundary_layout.statement_authority.count(),
                    core_calls.len,
                    self.poseidonBuffers().calls[0..self.poseidonBuffers().cursor],
                ) catch return error.V2CoreCohortMismatch;
                self.authority_id = nativeCoreAuthorityIdentity(self);
                self.validateCoreReady() catch |err|
                    return nativeV2CoreStageFailure("core-ready", err);
            }

            pub fn evaluations(self: *const NativeSegmentCoreV2) input_witness.Evaluations {
                return .{
                    .segment = &self.captured.evaluation,
                    .left = &self.inactive,
                    .right = &self.inactive,
                };
            }

            pub fn pcsInputs(self: *const NativeSegmentCoreV2) pcs_witness.InputWitness {
                const graph_digest = if (self.prepared_inputs_v4) |owned| owned.view().pcs_graph_digest else self.captured.pcs_circuit.graph().identity_digest;
                return .{ .lanes = .{
                    .{
                        .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID,
                        .circuit_id = PCS_SEGMENT_CIRCUIT_ID,
                        .graph_digest = graph_digest,
                        .input_values = self.pcs_active_inputs,
                    },
                    .{
                        .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID,
                        .circuit_id = PCS_LEFT_CIRCUIT_ID,
                        .graph_digest = graph_digest,
                        .input_values = self.pcs_inactive_inputs,
                    },
                    .{
                        .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID,
                        .circuit_id = PCS_RIGHT_CIRCUIT_ID,
                        .graph_digest = graph_digest,
                        .input_values = self.pcs_inactive_inputs,
                    },
                } };
            }

            pub fn validateCoreReady(self: *const NativeSegmentCoreV2) !void {
                try self.captured.evaluation.validateAgainst(&self.captured.circuit);
                try self.captured.pcs_evaluation.validateAgainst(
                    &self.captured.pcs_circuit,
                );
                try self.vm_air_prepared.validate();
                if (self.prepared_inputs_v4) |owned| {
                    owned.validateSource(self) catch |err| return nativeV2CoreStageFailure("prepared-input-source", err);
                    try self.complete_layout.validate(self.poseidonBuffers().calls[0..self.poseidonBuffers().cursor]);
                }
                try self.validateLocalCoreReady();
            }

            /// Operational validation of privately owned preparation. An absent
            /// projection preserves legacy mutable-source validation exactly.
            pub fn validatePreparedCoreReady(self: *const NativeSegmentCoreV2) !void {
                if (self.prepared_inputs_v4 == null) return self.validateCoreReady();
                try self.validateLocalCoreReady();
            }

            fn validateLocalCoreReady(self: *const NativeSegmentCoreV2) !void {
                try self.verifier_plans.vm.validate();
                try self.verifier_plans.recursion.validate();
                try self.authority.manifest.validate();
                const expected_public_lane = self.public_native_sum_lane;
                const retained_public_lane =
                    self.authority.public_native_sum_lane orelse
                    return error.V2CoreCohortMismatch;
                if (self.prepared_inputs_v4) |owned| {
                    try self.complete_layout.validateReceipt();
                    if (!std.meta.eql(self.complete_layout, owned.view().layout)) return error.V2CoreCohortMismatch;
                } else self.complete_layout.validate(
                    self.poseidonBuffers().calls[0..self.poseidonBuffers().cursor],
                ) catch return error.V2CoreCohortMismatch;
                if (self.authority.full_roster or
                    self.authority.segment_transcript_inputs != null or
                    self.authority.segment_transcript != null or
                    self.authority.segment_leaf_admission != null or
                    self.authority.vm_air == null or
                    !loweringLaneEql(retained_public_lane, expected_public_lane) or
                    !std.mem.eql(
                        u8,
                        &self.public_native_sum_authority_id,
                        &self.public_native_sum_lane.circuit_identity,
                    ) or !std.mem.eql(
                    u8,
                    &self.public_native_sum_evaluation.circuit_identity,
                    &self.public_native_sum_lane.circuit_identity,
                ) or std.mem.allEqual(
                    u8,
                    &self.public_native_sum_evaluation_id,
                    0,
                ) or
                    !std.meta.eql(self.authority.vm_air.?.prepared, self.vm_air_prepared) or
                    self.authority.manifest.roster_count != NATIVE_V2_CORE_ROW_COUNT or
                    self.authority.poseidon2_row_count != self.poseidonBuffers().calls.len or
                    self.poseidonBuffers().cursor != self.poseidonBuffers().calls.len or
                    self.boundary_prefix_count !=
                        self.complete_layout.boundary_prefix_call_count or
                    self.core_poseidon_call_count !=
                        self.complete_layout.verifier_core.count() catch 0 or
                    self.provider_main_ready != self.poseidonBuffers().outputs_ready or
                    !std.mem.eql(
                        u8,
                        &self.authority_id,
                        &nativeCoreAuthorityIdentity(self),
                    ))
                {
                    return error.V2CoreCohortMismatch;
                }
                for (
                    self.authority.manifest.roster_rows[0..self.authority.manifest.roster_count],
                    NATIVE_V2_CORE_FIRST_ROW..NATIVE_V2_CORE_LAST_ROW + 1,
                ) |actual, expected| if (actual != expected)
                    return error.V2CoreCohortMismatch;
            }

            pub fn validateComplete(self: *const NativeSegmentCoreV2) !void {
                try self.validateCoreReady();
                if (!self.provider_main_ready) return error.V2CoreCohortMismatch;
            }

            pub fn validatePreparedComplete(self: *const NativeSegmentCoreV2) !void {
                try self.validatePreparedCoreReady();
                if (!self.provider_main_ready) return error.V2CoreCohortMismatch;
            }

            pub fn finalizeSharedProviderMain(self: *NativeSegmentCoreV2) !void {
                self.validatePreparedCoreReady() catch |err|
                    return nativeV2CoreStageFailure("provider-preflight", err);
                if (self.provider_main_ready) return error.V2CoreCohortMismatch;
                fillPoseidonMain(
                    &self.authority,
                    &self.main_tree,
                    self.poseidonBuffersMut(),
                ) catch |err| return nativeV2CoreStageFailure("provider-main", err);
                self.provider_main_ready = true;
                // Provider output mutation is finalized here, before exposing
                // the ready owner to any operational reader.
                if (self.prepared_inputs_v4 != null) try self.complete_layout.validate(self.poseidonBuffers().calls);
                self.validatePreparedComplete() catch |err|
                    return nativeV2CoreStageFailure("provider-complete", err);
            }

            pub fn corePoseidonCalls(
                self: *const NativeSegmentCoreV2,
            ) ![]const shared_schedule_v2.Call {
                try self.validatePreparedCoreReady();
                return self.poseidonBuffers().calls[self.boundary_prefix_count..self.poseidonBuffers().cursor];
            }

            pub fn completePoseidonCalls(
                self: *const NativeSegmentCoreV2,
            ) ![]const shared_schedule_v2.Call {
                try self.validatePreparedCoreReady();
                return self.poseidonBuffers().calls[0..self.poseidonBuffers().cursor];
            }

            pub fn completeScheduleReceipt(
                self: *const NativeSegmentCoreV2,
            ) !shared_schedule_v2.SharedPoseidonCallLayoutV2 {
                try self.validatePreparedCoreReady();
                return self.complete_layout;
            }

            pub fn authorityIdentity(self: *const NativeSegmentCoreV2) ![32]u8 {
                try self.validatePreparedCoreReady();
                return self.authority_id;
            }

            pub const TranscriptPrefixAuthorityV1 = struct {
                authority_sha_id: [32]u8,
                layout_sha_id: [32]u8,
                call_buffer_sha_id: [32]u8,
                total_call_count: u32,
                public_wire_boundary_term_count: u32,
                public_wire_boundary_claimed_sum: QM31,
            };

            /// One-pass verifier-side export of the exact native-core transcript
            /// preimage retained by recursive child ingestion. This is a fixed value
            /// receipt, not a detached authority: the successful outer verifier seals
            /// it into its recursive witness before publication.
            pub fn transcriptPrefixAuthority(
                self: *const NativeSegmentCoreV2,
                relations: *const universal.UniversalRelations,
            ) !TranscriptPrefixAuthorityV1 {
                try self.validatePreparedCoreReady();
                try relations.validate();
                if (self.prepared_inputs_v4 == null) try self.authority.lowering_plan.validateAgainst(
                    self.authority.arithmetic_reference,
                );
                var term_count: u32 = 0;
                for (self.authority.lowering_plan.public_terms) |term| {
                    if (term.active_in != .segment) continue;
                    term_count = std.math.add(u32, term_count, 1) catch
                        return error.ArithmeticOverflow;
                }
                if (term_count == 0) return error.V2CoreCohortMismatch;
                return .{
                    .authority_sha_id = self.authority_id,
                    .layout_sha_id = self.complete_layout.identity,
                    .call_buffer_sha_id = self.complete_layout.call_buffer_id,
                    .total_call_count = self.complete_layout.total_call_count,
                    .public_wire_boundary_term_count = term_count,
                    .public_wire_boundary_claimed_sum = try self.authority.lowering_plan
                        .publicBoundaryClaim(
                        .segment_leaf,
                        relations,
                    ),
                };
            }

            /// Binds the native-leaf core authority before relation challenges. The
            /// schedule identity and call-buffer identity are both included: a cohort
            /// cannot retain the same circuit authority while substituting either the
            /// prefix/core partition or any individual provider call.
            pub fn mixAuthority(
                self: *const NativeSegmentCoreV2,
                channel_value: anytype,
            ) !void {
                try self.validatePreparedCoreReady();
                channel_value.mixU32s(&.{
                    NATIVE_V2_CORE_AUTHORITY_TRANSCRIPT_DOMAIN,
                    NATIVE_V2_CORE_FORMAT_VERSION,
                    NATIVE_V2_CORE_FIRST_ROW,
                    NATIVE_V2_CORE_LAST_ROW,
                    NATIVE_V2_CORE_PROVIDER_INSTANCE_COUNT,
                    self.complete_layout.total_call_count,
                });
                channel_value.mixU32s(&digestWords(self.authority_id));
                channel_value.mixU32s(&digestWords(self.complete_layout.identity));
                channel_value.mixU32s(&digestWords(
                    self.complete_layout.call_buffer_id,
                ));
            }

            pub fn componentLogSizes(
                self: *const NativeSegmentCoreV2,
            ) ![NATIVE_V2_CORE_ROW_COUNT]u32 {
                try self.validatePreparedCoreReady();
                return self.authority.log_sizes;
            }

            pub fn validateAgainstManifest(
                self: *const NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
            ) !void {
                try self.validatePreparedCoreReady();
                try self.validateManifestAfterCoreAdmission(manifest);
            }

            pub const ManifestAdmissionV2 = struct {
                authority_id: [32]u8,
                complete_calls: []const shared_schedule_v2.Call,
                complete_layout: shared_schedule_v2.SharedPoseidonCallLayoutV2,
            };

            /// Full source and provider-finalization admission followed by
            /// the exact manifest checks, once per synchronous consumer.
            /// The call slice remains borrowed; this is not a retained receipt
            /// authorizing later reads after mutable source changes.
            pub fn validateForManifest(
                self: *const NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
            ) !ManifestAdmissionV2 {
                try self.validateComplete();
                try self.validateManifestAfterCoreAdmission(manifest);
                const buffers = self.poseidonBuffers();
                return .{
                    .authority_id = self.authority_id,
                    .complete_calls = buffers.calls[0..buffers.cursor],
                    .complete_layout = self.complete_layout,
                };
            }

            fn validateManifestAfterCoreAdmission(
                self: *const NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
            ) !void {
                try manifest.validate();
                inline for (NATIVE_V2_CORE_FIRST_ROW..NATIVE_V2_CORE_LAST_ROW + 1) |row| {
                    const source = self.authority.manifest.placements[row] orelse
                        return error.V2CoreCohortMismatch;
                    const target = manifest.placements[row] orelse
                        return error.V2CoreCohortMismatch;
                    if (source.geometry.log_size != target.geometry.log_size or
                        source.geometry.preprocessed_columns !=
                            target.geometry.preprocessed_columns or
                        source.geometry.main_columns != target.geometry.main_columns or
                        source.geometry.interaction_columns !=
                            target.geometry.interaction_columns or
                        source.geometry.direct_constraints !=
                            target.geometry.direct_constraints or
                        source.geometry.interaction_batches !=
                            target.geometry.interaction_batches or
                        !std.mem.eql(
                            u8,
                            &source.geometry.semantic_digest,
                            &target.geometry.semantic_digest,
                        )) return error.V2CoreCohortMismatch;
                }
            }

            pub fn fillPreprocessedInto(
                self: *const NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
                destination: [][]M31,
            ) !void {
                try self.validateAgainstManifest(manifest);
                try publishNativeCoreTree(
                    &self.authority,
                    &self.preprocessed_tree,
                    manifest,
                    manifest_v2.PREPROCESSED_TREE_INDEX,
                    destination,
                );
            }

            pub fn fillMainInto(
                self: *const NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
                destination: [][]M31,
            ) !void {
                _ = try self.validateForManifest(manifest);
                try publishNativeCoreTree(
                    &self.authority,
                    &self.main_tree,
                    manifest,
                    manifest_v2.MAIN_TREE_INDEX,
                    destination,
                );
            }

            /// Cold, one-shot interaction preparation. Typed framework generation and
            /// exact per-domain auditing currently use bounded allocator scratch; the
            /// resulting Tree 2 and receipt are retained so publication, component
            /// construction, and repeated validation never replay that work.
            pub fn prepareInteractions(
                self: *NativeSegmentCoreV2,
                allocator: std.mem.Allocator,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
            ) !NativeSegmentCoreGeneratedV2 {
                const generator = @import("air/interaction_generator.zig").Host{};
                return prepareInteractionsWithGenerator(self, allocator, relations, provider_relations, &generator);
            }

            pub fn prepareInteractionsWithGenerator(
                self: *NativeSegmentCoreV2,
                allocator: std.mem.Allocator,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
                generator: anytype,
            ) !NativeSegmentCoreGeneratedV2 {
                if (self.generated_interactions) |generated| {
                    try generated.validateAgainst(self, relations, provider_relations);
                    return generated;
                }
                try self.validatePreparedComplete();
                try relations.validate();
                try provider_relations.validateAgainst(relations);
                // A failed cold preparation never becomes publishable. Clearing the
                // retained staging buffer makes an explicit retry deterministic too.
                @memset(self.interaction_tree.storage, M31.zero());
                var audit = ClosureAudit.init(allocator, false);
                defer audit.deinit();
                const claims: NativeInteractionClaims = if (self.prepared_inputs_v4) |owned| try fillNativeInteractionWithGenerator(allocator, &self.authority, &self.interaction_tree, owned.view().input_values, self.pcsInputs(), &self.invocations, self.prepared_query.value, self.preparedRootWitness(), &self.merkle_paths, self.poseidonBuffersMut(), &self.prepared_relation_rows, provider_relations, relations, &audit, generator) else blk: {
                    var arithmetic_storage: [MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation = undefined;
                    const legacy = try fillInteractionWithGenerator(allocator, &self.authority, &self.interaction_tree, self.evaluations(), self.pcsInputs(), try buildArithmeticEvaluations(
                        &self.authority,
                        self.captured,
                        &self.inactive,
                        self.public_native_sum_evaluation,
                        &arithmetic_storage,
                    ), &self.invocations, self.prepared_query.value, self.captured.merkleRootWitness(), &self.merkle_paths, self.poseidonBuffers(), &self.prepared_relation_rows, provider_relations, relations, &audit, generator);
                    break :blk .{ .claims = nativeCoreClaims(legacy), .poseidon2_partials = legacy.poseidon2, .public_boundaries = legacy.public_boundaries };
                };
                var result = NativeSegmentCoreGeneratedV2{
                    .authority_id = self.authority_id,
                    .schedule_id = self.complete_layout.identity,
                    .relation_registry_id = relations.registry_order_digest,
                    .provider_relation_id = try provider_relations.identityDigest(),
                    .claims = claims.claims,
                    .poseidon2_partials = claims.poseidon2_partials,
                    .audits = audit.rows[NATIVE_V2_CORE_FIRST_ROW .. NATIVE_V2_CORE_LAST_ROW + 1].*,
                    .identity = undefined,
                };
                result.identity = nativeCoreGeneratedIdentity(&result);
                try result.validateAgainst(self, relations, provider_relations);
                self.generated_interactions = result;
                return result;
            }

            /// Allocation-free publication of an already prepared interaction tree.
            /// `prepareInteractions` must have succeeded before the first external
            /// write, keeping the destination fail-atomic and the hot path copy-only.
            pub fn fillInteractionInto(
                self: *const NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
                destination: [][]M31,
            ) !NativeSegmentCoreGeneratedV2 {
                try self.validateAgainstManifest(manifest);
                const generated = self.generated_interactions orelse
                    return error.V2CoreCohortMismatch;
                try publishNativeCoreTree(
                    &self.authority,
                    &self.interaction_tree,
                    manifest,
                    manifest_v2.INTERACTION_TREE_INDEX,
                    destination,
                );
                return generated;
            }

            pub fn rebuildGeneratedInteractions(
                self: *NativeSegmentCoreV2,
                allocator: std.mem.Allocator,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
            ) !NativeSegmentCoreGeneratedV2 {
                return self.prepareInteractions(
                    allocator,
                    relations,
                    provider_relations,
                );
            }

            /// Cold, challenge-independent projection of rows 18--34 into an exact
            /// tuple ledger. Logical rows are either the retained Tree-1 authority or
            /// are deterministically rebuilt from the same sealed capture. The
            /// lowering plan's canonical graph anchors are appended only after every
            /// committed core row: they are verifier-derived constants/zero outputs,
            /// never a detached prover-supplied balancing claim.
            pub fn appendTupleContributions(
                self: *const NativeSegmentCoreV2,
                allocator: std.mem.Allocator,
                ledger: *TupleLedger,
                domain_mask: u64,
            ) !void {
                try self.validatePreparedComplete();
                try appendNativeSegmentCoreTupleContributions(
                    self,
                    allocator,
                    ledger,
                    domain_mask,
                );
            }

            pub fn initComponents(
                self: *NativeSegmentCoreV2,
                manifest: *const manifest_v2.Manifest,
                relations: *const universal.UniversalRelations,
                provider_relations: *const shared_provider.SharedProviderRelations,
                generated: *const NativeSegmentCoreGeneratedV2,
            ) !NativeSegmentCoreComponentsV2 {
                return initNativeSegmentCoreComponents(
                    self,
                    manifest,
                    relations,
                    provider_relations,
                    generated,
                );
            }
        };
    };
}
