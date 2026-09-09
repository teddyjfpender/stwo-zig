//! Witness-free components for the admitted SegmentV2 39-row circuit.
//! The caller must independently admit the exact manifest, preprocessing root,
//! and shape parameters. This owner authenticates the canonical AIRs and owns
//! their verifier adapters; supplied claims remain untrusted STARK inputs.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const manifest_mod = air.segment_outer_adapter_manifest_v2;
const native_parameters = @import("recursive_fri_component_parameters.zig");
const provider = air.universal_shared_provider;
const range = air.range_check_8_8_bridge;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const composition_v3 = frontend.recursion.recursion_air_composition_circuit_v3;
const segment_recorder = composition_v3.segment_recorder_v3;
pub const Relations = air.universal_challenges.UniversalRelations;

const logical_rows = air.segment_leaf_catalog_v2.LOGICAL_ROWS;

pub const AdmissionParametersV1 = struct {
    query_reference: air.query_bits_witness.Reference,
    poseidon_active_rows: u32,

    pub fn validate(self: AdmissionParametersV1, manifest: *const manifest_mod.Manifest) ![manifest_mod.COMPONENT_COUNT]u32 {
        try manifest.validate();
        var logs: [manifest_mod.COMPONENT_COUNT]u32 = undefined;
        for (manifest.placements, &logs) |placement, *log|
            log.* = (placement orelse return error.InvalidSegmentVerifierAdmission).geometry.log_size;
        try self.query_reference.validate();
        const query_rows = try std.math.add(u64, self.query_reference.vm.query_count, try std.math.mul(u64, 2, self.query_reference.recursion.query_count));
        if (query_rows > (@as(u64, 1) << @intCast(logs[@intFromEnum(manifest_mod.ComponentKey.query_bits)])) or
            self.poseidon_active_rows > (@as(u64, 1) << @intCast(logs[@intFromEnum(manifest_mod.ComponentKey.poseidon2)])))
            return error.InvalidSegmentVerifierAdmission;
        return logs;
    }
};

pub const ClaimsV1 = struct {
    values: [manifest_mod.COMPONENT_COUNT]QM31,
    poseidon_partials: [2]QM31,
    /// Required by the separately admitted q193 transcript. Absence preserves
    /// the original development wire; nonce zero is still a present nonce.
    interaction_pow: ?u64 = null,

    pub const jsonStringify = @import("recursive_detached_claims_v1.zig").jsonStringify;

    pub fn vector(self: ClaimsV1, manifest: *const manifest_mod.Manifest) !manifest_mod.ClaimVector {
        var result = try manifest_mod.ClaimVector.init(manifest);
        for (self.values, 0..) |value, index| {
            try canonical(value);
            try result.bind(@enumFromInt(index), value);
        }
        for (self.poseidon_partials) |partial| try canonical(partial);
        if (!self.poseidon_partials[0].add(self.poseidon_partials[1]).eql(self.values[@intFromEnum(manifest_mod.ComponentKey.poseidon2)]))
            return error.InvalidSegmentVerifierClaims;
        try (frontend.recursion.segment_statement_outer_components_v2.ClaimsV2{ .row10_inactive = self.values[10], .row11_statement = self.values[11] }).validate();
        try result.sealClaims(manifest);
        return result;
    }
};

fn Component(comptime entry: anytype) type {
    @setEvalBranchQuota(500_000);
    return switch (entry.row) {
        .statement_source_v2 => air.segment_boundary_components_v2.StatementAdapter,
        .public_logup_source_v2 => air.segment_boundary_components_v2.PublicLogUpAdapter,
        .segment_publication_input_provider_v2 => air.segment_publication_input_provider_component_v2.AdapterForManifest(manifest_mod),
        else => air.universal_typed_component.ComponentForManifest(entry.Air, air.universal_relation_binding.Binding(entry.Air), manifest_mod),
    };
}
fn Tuple(comptime definitions: bool) type {
    var types: [logical_rows.len]type = undefined;
    for (logical_rows, 0..) |entry, index| types[index] = if (definitions) entry.Air.Definition else Component(entry);
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
        definitions: Tuple(true),
        initialized: usize = 0,
        logical: Tuple(false),
        range_definition: range.Definition,
        range_initialized: bool = false,
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
            .definitions = undefined,
            .logical = undefined,
            .range_definition = undefined,
            .range_executor = undefined,
            .poseidon = undefined,
            .range_component = undefined,
            .gate = gate,
        };
        const self: *Self = @ptrCast(storage);
        errdefer self.deinit();
        storage.providers = try provider.SharedProviderRelations.init(&storage.relations);
        inline for (logical_rows, 0..) |entry, index| {
            storage.definitions[index] = if (entry.requires_location) try entry.Air.build(allocator, .generated) else try entry.Air.build(allocator);
            storage.initialized += 1;
            const relation = if (comptime entry.row == .statement_source_v2 or entry.row == .public_logup_source_v2)
                try entry.Air.authenticate(&storage.definitions[index])
            else
                try air.universal_relation_binding.Binding(entry.Air).authenticate(&storage.definitions[index]);
            storage.logical[index] = try Component(entry).init(&storage.definitions[index], relation, &storage.manifest, @enumFromInt(@intFromEnum(entry.row)), logs[@intFromEnum(entry.row)], try parametersFor(entry, parameters), &storage.relations, claims.values[@intFromEnum(entry.row)]);
            if (comptime index < air.universal_catalog.LOGICAL_ROWS.len) try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
        }
        storage.poseidon = try provider.Poseidon2AdapterForManifest(manifest_mod).init(&storage.manifest, logs[34], parameters.poseidon_active_rows, &storage.providers, &storage.relations, claims.poseidon_partials);
        try storage.gate.append(&storage.manifest, try storage.poseidon.binding(&storage.manifest));
        storage.range_definition = try range.build(allocator);
        storage.range_initialized = true;
        storage.range_executor = try range.Executor.init(&storage.range_definition, &try range.Binding.canonical(&storage.range_definition));
        storage.range_component = try provider.RangeCheck8x8AdapterForManifest(manifest_mod).init(&storage.range_definition, &storage.range_executor, &storage.manifest, &storage.providers, &storage.relations, claims.values[35]);
        try storage.gate.append(&storage.manifest, try storage.range_component.binding(&storage.manifest));
        inline for (air.universal_catalog.LOGICAL_ROWS.len..logical_rows.len) |index|
            try storage.gate.append(&storage.manifest, try storage.logical[index].binding(&storage.manifest));
        try storage.gate.sealGate(&storage.manifest);
        return self;
    }

    pub fn deinit(self: *Self) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        inline for (0..logical_rows.len) |index| if (index < storage.initialized) storage.definitions[index].deinit();
        if (storage.range_initialized) storage.range_definition.deinit();
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

fn parametersFor(comptime entry: anytype, admitted: AdmissionParametersV1) ![Component(entry).PARAMETER_COLUMN_COUNT]M31 {
    const row = @intFromEnum(entry.row);
    if (comptime row >= 36 or row == 10 or row == 11)
        return @splat(M31.zero());
    if (comptime row < 10)
        return @field(frontend.recursion.segment_transcript_outer_components_v2.Parameters.segmentV2(), @tagName(entry.row));
    if (comptime row < 18) {
        const fields = .{ "publication_header", "native_public_sums", "publication_seal", "boundary_bridge", "native_challenges", "control_relay" };
        return @field(frontend.recursion.segment_public_outer_components_v2.Parameters.segmentV2(), fields[row - 12]);
    }
    return switch (entry.row) {
        .vm_air_composition_input => native_parameters.vmInputParameters(.segment_leaf),
        .vm_air_composition_control => air.control_slice_witness.ProofKind.segment_leaf.selectors()[0..2].*,
        .query_bits => try native_parameters.queryBitsParameters(admitted.query_reference, .segment_leaf),
        .query_mapping => native_parameters.queryMappingParameters(.segment_leaf),
        .merkle_root => native_parameters.merkleRootParameters(.segment_leaf),
        .trace_merkle => native_parameters.traceMerkleParameters(.segment_leaf),
        .pcs_deep_input => native_parameters.pcsParameters(.segment_leaf),
        .fri_merkle_leaf => native_parameters.friLeafParameters(.segment_leaf),
        .fri_merkle_node => air.fri_merkle_leaf_witness.ProofKind.segment_leaf.selectors()[0..2].*,
        .fri_merkle_anchor => native_parameters.friAnchorParameters(.segment_leaf),
        .fri_verifier_control => native_parameters.controlParameters(.segment_leaf),
        .fri_verifier_input => native_parameters.inputParameters(.segment_leaf),
        .qm31_mul, .qm31_inv, .linear_ops => air.fri_verifier_input_witness.ProofKind.segment_leaf.selectors(),
        .merkle_path => .{},
        else => unreachable,
    };
}
fn canonical(value: QM31) !void {
    for (value.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus) return error.InvalidSegmentVerifierClaims;
}

// A catalog-only fixture deliberately has no native capture, source rows, or
// prepared cohort. These IDs are test inputs, not a detached key admission.
fn testAdmission() !struct { manifest: manifest_mod.Manifest, parameters: AdmissionParametersV1 } {
    const boundary_manifest = frontend.recursion.segment_leaf_outer_authority_v2;
    const boundary_air = frontend.recursion.segment_leaf_outer_air_v2;
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
        .provider_authority_sha_id = frontend.recursion.segment_publication_input_provider_authority_v2.sourceAuthorityShaId(),
    });
    const lane: air.query_bits_witness.LaneProfile = .{ .query_count = 3, .lifting_log_size = 4, .trace_tree_count = 4, .fri_layer_count = 2 };
    return .{ .manifest = manifest, .parameters = .{ .query_reference = try air.query_bits_witness.Reference.seal(lane, lane), .poseidon_active_rows = 1 } };
}

test "SegmentV2 witness-free verifier owns all39 canonical adapters and untrusted claims" {
    var admitted = try testAdmission();
    var relations = Relations.dummy();
    var claims: ClaimsV1 = .{ .values = @splat(QM31.one()), .poseidon_partials = .{ QM31.one(), QM31.zero() } };
    claims.values[10] = QM31.zero();
    const expected_manifest = admitted.manifest;
    const owner = try OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims);
    defer owner.deinit();
    // Destroy every external input before querying or exporting the adapters.
    admitted = undefined;
    relations = undefined;
    claims = undefined;
    const components = try owner.verifierComponents();
    try std.testing.expectEqual(@as(usize, 39), components.len);
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

test "SegmentV2 witness-free verifier rejects malformed admission and inactive or provider claims" {
    var admitted = try testAdmission();
    const relations = Relations.dummy();
    var claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    claims.values[10] = QM31.one();
    try std.testing.expectError(error.InactiveRowInvariantMismatch, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    claims.values[10] = QM31.zero();
    claims.poseidon_partials[0] = QM31.one();
    try std.testing.expectError(error.InvalidSegmentVerifierClaims, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    claims.poseidon_partials[0] = QM31.zero();
    admitted.parameters.poseidon_active_rows = 33;
    try std.testing.expectError(error.InvalidSegmentVerifierAdmission, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
    admitted.parameters.poseidon_active_rows = 1;
    admitted.manifest.placements[38] = null;
    try std.testing.expectError(error.ManifestSealMismatch, OwnedComponentsV1.init(std.testing.allocator, &admitted.manifest, admitted.parameters, &relations, claims));
}

test "SegmentV2 witness-free verifier releases its owner after initial definition allocation failure" {
    const admitted = try testAdmission();
    const relations = Relations.dummy();
    const claims: ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    for (0..3) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        try std.testing.expectError(error.OutOfMemory, OwnedComponentsV1.init(failing.allocator(), &admitted.manifest, admitted.parameters, &relations, claims));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

test "SegmentV2 witness-free recording keeps all39 claims and two provider partials symbolic" {
    const allocator = std.testing.allocator;
    const admitted = try testAdmission();
    const recorder = segment_recorder.graph_recorder;
    const capture_layout = composition_v3.capture_layout_v3;
    var capture = try frontend.testing.recursion_air_composition_v3.CaptureFixture.init(allocator, &admitted.manifest);
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
