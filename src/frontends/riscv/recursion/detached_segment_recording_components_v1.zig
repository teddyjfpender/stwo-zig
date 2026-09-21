//! Witness-free components for the admitted SegmentV2 39-row circuit.
//! The caller must independently admit the exact manifest, preprocessing root,
//! and shape parameters. This owner authenticates the canonical AIRs and owns
//! their verifier adapters; supplied claims remain untrusted STARK inputs.
const recursion = struct {
    const detached_segment_admission_v1 = @import("detached_segment_admission_v1.zig");
    const detached_segment_definitions_v1 = @import("detached_segment_definitions_v1.zig");
    const detached_segment_verifier_components_v1 = @import("detached_segment_verifier_components_v1.zig");
    const recursion_air_composition_circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
    const segment_leaf_outer_air_v2 = @import("segment_leaf_outer_air_v2.zig");
    const segment_leaf_outer_authority_v2 = @import("segment_leaf_outer_authority_v2.zig");
    const segment_leaf_parameters_v2 = @import("segment_leaf_parameters_v2.zig");
    const segment_publication_input_provider_authority_v2 = @import("segment_publication_input_provider_authority_v2.zig");
};
const air = struct {
    const query_bits_witness = @import("air/query_bits_witness.zig");
    const range_check_8_8_bridge = @import("air/range_check_8_8_bridge.zig");
    const segment_boundary_components_v2 = @import("air/segment_boundary_components_v2.zig");
    const segment_leaf_catalog_v2 = @import("air/segment_leaf_catalog_v2.zig");
    const segment_outer_adapter_manifest_v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const segment_outer_typed_catalog_v2 = @import("air/segment_outer_typed_catalog_v2.zig");
    const segment_publication_input_provider_component_v2 = @import("air/segment_publication_input_provider_component_v2.zig");
    const universal_catalog = @import("air/universal_catalog.zig");
    const universal_challenges = @import("air/universal_challenges.zig");
    const universal_manifest = @import("air/universal_manifest.zig");
    const universal_relation_binding = @import("air/universal_relation_binding.zig");
    const universal_shared_provider = @import("air/universal_shared_provider.zig");
    const universal_typed_component = @import("air/universal_typed_component.zig");
    const vm_public_logup_control_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");
};
const testing_support = struct {
    const recursion_air_composition_v3 = @import("recursion_air_composition_circuit_v3_test_support.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const manifest_mod = air.segment_outer_adapter_manifest_v2;
const parametersFor = recursion.segment_leaf_parameters_v2.parametersFor;
const provider = air.universal_shared_provider;
const range = air.range_check_8_8_bridge;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const segment_recorder = composition_v3.segment_recorder_v3;
pub const Relations = air.universal_challenges.UniversalRelations;

const PureOwner = recursion.detached_segment_verifier_components_v1.OwnedComponentsV1;
const definitions_mod = recursion.detached_segment_definitions_v1;
const logical_rows = air.segment_leaf_catalog_v2.LOGICAL_ROWS;

const admission = recursion.detached_segment_admission_v1;
pub const AdmissionParametersV1 = admission.AdmissionParametersV1;
pub const ClaimsV1 = admission.ClaimsV1;

fn Component(comptime entry: anytype) type {
    @setEvalBranchQuota(500_000);
    return switch (entry.row) {
        .statement_source_v2 => air.segment_boundary_components_v2.StatementAdapter,
        .public_logup_source_v2 => air.segment_boundary_components_v2.PublicLogUpAdapter,
        .segment_publication_input_provider_v2 => air.segment_publication_input_provider_component_v2.AdapterForManifest(manifest_mod),
        else => air.universal_typed_component.ComponentForManifest(entry.Air, air.universal_relation_binding.Binding(entry.Air), manifest_mod),
    };
}
fn ComponentTuple() type {
    var types: [logical_rows.len]type = undefined;
    for (logical_rows, 0..) |entry, index| types[index] = Component(entry);
    return std.meta.Tuple(&types);
}

pub const OwnedComponentsV1 = opaque {
    const Self = @This();
    const Storage = struct {
        allocator: std.mem.Allocator,
        manifest: manifest_mod.Manifest,
        parameters: AdmissionParametersV1,
        relations: Relations,
        providers: provider.SharedProviderRelations,
        definitions: definitions_mod.Definitions,
        logical: ComponentTuple(),
        range_executor: range.Executor,
        poseidon: provider.Poseidon2AdapterForManifest(manifest_mod),
        range_component: provider.RangeCheck8x8AdapterForManifest(manifest_mod),
        gate: manifest_mod.ProofGate,
    };

    pub fn init(allocator: std.mem.Allocator, manifest: *const manifest_mod.Manifest, parameters: AdmissionParametersV1, relations: *const Relations, claims: ClaimsV1) !*Self {
        const logs = try parameters.validate(manifest);
        _ = try claims.vector(manifest);
        try relations.validate();
        const gate = try manifest_mod.ProofGate.init(manifest);
        const storage = try allocator.create(Storage);
        storage.* = .{
            .allocator = allocator,
            .manifest = manifest.*,
            .parameters = parameters,
            .relations = relations.*,
            .providers = undefined,
            .definitions = definitions_mod.Definitions.init(allocator),
            .logical = undefined,
            .range_executor = undefined,
            .poseidon = undefined,
            .range_component = undefined,
            .gate = gate,
        };
        const self: *Self = @ptrCast(storage);
        errdefer self.deinit();
        storage.providers = try provider.SharedProviderRelations.init(&storage.relations);
        inline for (logical_rows, 0..) |entry, index| {
            try storage.definitions.initLogical(index);
            const relation = if (comptime entry.row == .statement_source_v2 or entry.row == .public_logup_source_v2)
                try entry.Air.authenticate(&storage.definitions.logical[index])
            else
                try air.universal_relation_binding.Binding(entry.Air).authenticate(&storage.definitions.logical[index]);
            storage.logical[index] = try Component(entry).init(&storage.definitions.logical[index], relation, &storage.manifest, @enumFromInt(@intFromEnum(entry.row)), logs[@intFromEnum(entry.row)], try parametersFor(entry, parameters), &storage.relations, claims.values[@intFromEnum(entry.row)]);
            if (comptime index < air.universal_catalog.LOGICAL_ROWS.len) try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
        }
        storage.poseidon = try provider.Poseidon2AdapterForManifest(manifest_mod).init(&storage.manifest, logs[34], parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
        try storage.gate.append(&storage.manifest, try storage.poseidon.binding(&storage.manifest));
        try storage.definitions.initRange();
        storage.range_executor = try range.Executor.init(&storage.definitions.range_definition, &try range.Binding.canonical(&storage.definitions.range_definition));
        storage.range_component = try provider.RangeCheck8x8AdapterForManifest(manifest_mod).init(&storage.definitions.range_definition, &storage.range_executor, &storage.manifest, &storage.providers, &storage.relations, claims.values[35]);
        try storage.gate.append(&storage.manifest, try storage.range_component.binding(&storage.manifest));
        inline for (air.universal_catalog.LOGICAL_ROWS.len..logical_rows.len) |index|
            try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
        try storage.gate.sealGate(&storage.manifest);
        return self;
    }

    pub fn deinit(self: *Self) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        storage.definitions.deinit();
        storage.allocator.destroy(storage);
    }

    /// Every pointer in these adapters targets this immutable heap owner.
    pub fn verifierComponents(self: *const Self) ![]const core.air.components.Component {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        return storage.gate.verifierSlice();
    }

    /// Populate an empty proof gate from this owner's admitted AIRs.
    /// The copied adapters borrow this immutable owner, which must
    /// outlive the gate. The selected manifest remains an explicit input.
    pub fn appendToGate(self: *const Self, manifest: *const manifest_mod.Manifest, gate: *manifest_mod.ProofGate) !void {
        if (gate.count != 0 or gate.sealed) return error.InvalidSegmentVerifierAdmission;
        const storage: *const Storage = @ptrCast(@alignCast(self));
        try storage.gate.validate(manifest);
        gate.* = storage.gate;
    }

    /// Record the same admitted adapters in proof order. Every sampled value,
    /// relation draw and claim comes from the recorder's symbolic inputs; the
    /// concrete verifier values retained by this owner never become constants.
    /// The returned graph accumulation is not a proof-verification receipt.
    pub fn recordCompositionV3(self: *const Self, program: *segment_recorder.SegmentProgramRecorderV3) !segment_recorder.ProgramResultV3 {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        inline for (logical_rows[0..air.universal_catalog.LOGICAL_ROWS.len], 0..) |entry, index|
            _ = try program.recordTypedComponent(entry.row, &storage.logical[index]);
        _ = try program.recordPoseidonProvider(&storage.poseidon);
        _ = try program.recordRangeCheck8x8Provider(&storage.range_component);
        inline for (logical_rows[air.universal_catalog.LOGICAL_ROWS.len..], air.universal_catalog.LOGICAL_ROWS.len..) |entry, index|
            _ = try program.recordTypedComponent(entry.row, &storage.logical[index]);
        return program.finishProgram();
    }
};

// A catalog-only fixture deliberately has no native capture, source rows, or
// prepared cohort. These IDs are test inputs, not a detached key admission.
fn testAdmission() !struct { manifest: manifest_mod.Manifest, parameters: AdmissionParametersV1 } {
    const boundary_manifest = recursion.segment_leaf_outer_authority_v2;
    const boundary_air = recursion.segment_leaf_outer_air_v2;
    const Fixtures = struct {
        fn boundaryComponents(
            statement_log_size: u8,
        ) [boundary_manifest.COMPONENT_COUNT]boundary_manifest.ComponentGeometryV2 {
            return .{
                .{
                    .kind = .statement_source,
                    .component_tag = boundary_manifest.STATEMENT_COMPONENT_TAG,
                    .logical_rows = (@as(u32, 1) << @intCast(statement_log_size - 1)) + 1,
                    .trace_log_size = statement_log_size,
                    .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
                    .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
                    .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
                    .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
                    .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
                    .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
                    .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
                    .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
                },
                .{
                    .kind = .public_logup_source,
                    .component_tag = boundary_manifest.PUBLIC_LOGUP_COMPONENT_TAG,
                    .logical_rows = boundary_manifest.PUBLIC_LOGUP_LOGICAL_ROWS,
                    .trace_log_size = boundary_manifest.PUBLIC_LOGUP_TRACE_LOG_SIZE,
                    .trace_rows = boundary_manifest.PUBLIC_LOGUP_TRACE_ROWS,
                    .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
                    .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
                    .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
                    .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
                    .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
                    .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
                    .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
                },
            };
        }
    };
    var logs: air.universal_manifest.LogSizes = @splat(4);
    logs[11] = 8;
    logs[17] = air.vm_public_logup_control_witness_v2.TRACE_LOG_SIZE;
    logs[34] = 5;
    logs[35] = range.LOG_SIZE;
    const catalog = try air.segment_outer_typed_catalog_v2.build(logs, Fixtures.boundaryComponents(8));
    const manifest = try manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = @splat(1),
        .statement_manifest_id = @splat(2),
        .public_manifest_id = @splat(3),
        .boundary_manifest_id = @splat(4),
        .boundary_authority_sha_id = @splat(5),
        .provider_authority_sha_id = recursion.segment_publication_input_provider_authority_v2.sourceAuthorityShaId(),
    });
    const lane: air.query_bits_witness.LaneProfile = .{ .query_count = 3, .lifting_log_size = 4, .trace_tree_count = 4, .fri_layer_count = 2 };
    return .{ .manifest = manifest, .parameters = .{ .query_reference = try air.query_bits_witness.Reference.seal(lane, lane), .poseidon_active_rows = 1 } };
}

pub fn testCanonicalAdapters() !void {
    var admitted = try testAdmission();
    var relations = Relations.dummy();
    var claims: ClaimsV1 = .{ .values = @splat(QM31.one()), .poseidon_partials = .{ QM31.one(), QM31.zero() } };
    claims.values[10] = QM31.zero();
    const expected_manifest = admitted.manifest;
    const owner = try OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims);
    defer owner.deinit();
    const pure = try PureOwner.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims);
    defer pure.deinit();
    // Destroy every external input before querying or exporting the adapters.
    admitted = undefined;
    relations = undefined;
    claims = undefined;
    const components = try owner.verifierComponents();
    try std.testing.expectEqual(@as(usize, 39), components.len);
    const actual = try pure.verifierComponents();
    try std.testing.expectEqual(components.len, actual.len);
    for (components, actual) |left, right| {
        try std.testing.expectEqual(left.nConstraints(), right.nConstraints());
        try std.testing.expectEqual(left.maxConstraintLogDegreeBound(), right.maxConstraintLogDegreeBound());
        try std.testing.expectEqual(left.compositionLogSplit(), right.compositionLogSplit());
        const left_indices = try left.preprocessedColumnIndices(std.testing.allocator);
        defer std.testing.allocator.free(left_indices);
        const right_indices = try right.preprocessedColumnIndices(std.testing.allocator);
        defer std.testing.allocator.free(right_indices);
        try std.testing.expectEqualSlices(usize, left_indices, right_indices);
    }
    var constraints: usize = 0;
    for (components) |component| constraints += component.nConstraints();
    try std.testing.expectEqual(@as(usize, expected_manifest.total_constraints), constraints);
    const storage: *const OwnedComponentsV1.Storage = @ptrCast(@alignCast(owner));
    inline for (logical_rows, 0..) |entry, index| {
        _ = try storage.logical[index].binding(&expected_manifest);
        const expected = if (comptime entry.row == .statement_input) QM31.zero() else QM31.one();
        try std.testing.expect(storage.logical[index].claimed_sum.eql(expected));
    }
    _ = try storage.poseidon.binding(&expected_manifest);
    _ = try storage.range_component.binding(&expected_manifest);
    var gate = try manifest_mod.ProofGate.init(&expected_manifest);
    try owner.appendToGate(&expected_manifest, &gate);
    try std.testing.expectEqual(@as(usize, 39), (try gate.verifierSlice()).len);
    try std.testing.expectError(error.InvalidSegmentVerifierAdmission, owner.appendToGate(&expected_manifest, &gate));
}

pub fn testMalformedAdmission() !void {
    var admitted = try testAdmission();
    const relations = Relations.dummy();
    var claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    claims.values[10] = QM31.one();
    try std.testing.expectError(error.InactiveRowInvariantMismatch, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    try std.testing.expectError(error.InactiveRowInvariantMismatch, PureOwner.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    claims.values[10] = QM31.zero();
    claims.poseidon_partials[0] = QM31.one();
    try std.testing.expectError(error.InvalidSegmentVerifierClaims, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    try std.testing.expectError(error.InvalidSegmentVerifierClaims, PureOwner.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    claims.poseidon_partials[0] = QM31.zero();
    admitted.parameters.poseidon_active_rows = 33;
    try std.testing.expectError(error.InvalidSegmentVerifierAdmission, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    try std.testing.expectError(error.InvalidSegmentVerifierAdmission, PureOwner.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    admitted.parameters.poseidon_active_rows = 1;
    admitted.manifest.placements[38] = null;
    try std.testing.expectError(error.ManifestSealMismatch, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    try std.testing.expectError(error.ManifestSealMismatch, PureOwner.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
}

pub fn testAllocationFailure() !void {
    const admitted = try testAdmission();
    const relations = Relations.dummy();
    const claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    inline for (.{ OwnedComponentsV1, PureOwner }) |Owner| {
        for ([_]usize{ 0, 1, 8, 32, 128, 512, 2048 }) |fail_index| {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
            try std.testing.expectError(error.OutOfMemory, Owner.init(failing.allocator(), &admitted.manifest, admitted.parameters, &relations, claims));
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
    }
}

pub fn testSymbolicClaims() !void {
    const allocator = std.testing.allocator;
    const admitted = try testAdmission();
    const recorder = segment_recorder.graph_recorder;
    const capture_layout = composition_v3.capture_layout_v3;
    var capture = try testing_support.recursion_air_composition_v3.CaptureFixture.init(allocator, &admitted.manifest);
    defer capture.deinit();
    var layout = try capture_layout.CaptureLayoutV3.initSegment(allocator, &admitted.manifest, capture.view());
    defer layout.deinit();

    const Recording = struct {
        fn record(owner: *const OwnedComponentsV1, manifest: *const manifest_mod.Manifest, sample_layout: *const capture_layout.CaptureLayoutV3) !recorder.Circuit {
            var builder = recorder.Builder.init(std.testing.allocator);
            defer builder.deinit();
            const input_count: usize = @as(usize, sample_layout.sampled_value_count) + segment_recorder.COMPOSITION_CLAIM_INPUT_COUNT + 2 * air.universal_challenges.RELATION_COUNT + 2;
            try builder.reserve(input_count, @as(usize, manifest.total_constraints) * 8);
            const samples = try std.testing.allocator.alloc(recorder.Scalar, sample_layout.sampled_value_count);
            defer std.testing.allocator.free(samples);
            for (samples) |*sample| sample.* = (try builder.input()).value;
            var claims: [segment_recorder.COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar = undefined;
            for (&claims) |*claim| claim.* = (try builder.input()).value;
            var draws: [air.universal_challenges.RELATION_COUNT][2]recorder.Scalar = undefined;
            for (&draws) |*pair| for (pair) |*draw| {
                draw.* = (try builder.input()).value;
            };
            const alpha = (try builder.input()).value;
            const seed = (try builder.input()).value;
            try builder.activate();
            const challenges = try recorder.ChallengeSet.init(draws);
            var denominators: recorder.DenominatorCache = .{null} ** core.circle.M31_CIRCLE_LOG_ORDER;
            var program = try segment_recorder.SegmentProgramRecorderV3.init(&builder, manifest, sample_layout, samples, &claims, &challenges, alpha, recorder.pointFromSeed(seed), &denominators);
            try std.testing.expectEqual(@as(usize, 41), claims.len);
            for (0..39) |row| try std.testing.expect(std.meta.eql(claims[row], program.claimedSum(@enumFromInt(row))));
            try std.testing.expect(std.meta.eql(claims[39], program.poseidonPartialClaim(0)));
            try std.testing.expect(std.meta.eql(claims[40], program.poseidonPartialClaim(1)));
            const result = try owner.recordCompositionV3(&program);
            try std.testing.expectEqual(@as(u8, 39), result.row_count);
            try std.testing.expectEqual(@as(usize, manifest.total_constraints), result.constraint_count);
            try builder.constrainZero(result.accumulation);
            builder.deactivate();
            var circuit = try builder.finish();
            errdefer circuit.deinit();
            try std.testing.expectEqual(input_count, circuit.input_count);
            for (0..claims.len) |slot|
                try std.testing.expect(std.meta.activeTag(circuit.nodes[sample_layout.sampled_value_count + slot].op) == .input);
            return circuit;
        }
    };

    var first_claims: ClaimsV1 = .{ .values = @splat(QM31.one()), .poseidon_partials = .{ QM31.one(), QM31.zero() } };
    first_claims.values[10] = QM31.zero();
    const first_relations = Relations.dummy();
    const first = try OwnedComponentsV1.init(allocator, &admitted.manifest, admitted.parameters, &first_relations, first_claims);
    defer first.deinit();
    var first_circuit = try Recording.record(first, &admitted.manifest, &layout);
    defer first_circuit.deinit();

    const two = QM31.fromU32Unchecked(2, 0, 0, 0);
    var second_claims: ClaimsV1 = .{ .values = @splat(two), .poseidon_partials = .{ QM31.zero(), two } };
    second_claims.values[10] = QM31.zero();
    const other_draws: [air.universal_challenges.DRAW_COUNT]QM31 = @splat(two);
    const second_relations = Relations.fromDraws(&other_draws);
    const second = try OwnedComponentsV1.init(allocator, &admitted.manifest, admitted.parameters, &second_relations, second_claims);
    defer second.deinit();
    var second_circuit = try Recording.record(second, &admitted.manifest, &layout);
    defer second_circuit.deinit();
    try std.testing.expectEqualDeep(first_circuit.identity_digest, second_circuit.identity_digest);
    try std.testing.expectEqualDeep(first_circuit.nodes, second_circuit.nodes);
    try std.testing.expectEqualDeep(first_circuit.outputs, second_circuit.outputs);
}
