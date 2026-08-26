//! Internal V3 authority validation and mutation coverage; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_v3_canonical_empty_program_v3.zig");
const dependency_1 = @import("recursion_air_composition_circuit_v3_program_roster_v3.zig");
const dependency_2 = @import("recursion_air_composition_circuit_v3_circuit_view_v3.zig");
const dependency_3 = @import("recursion_air_composition_circuit_v3_heterogeneous_session_v3.zig");
const dependency_4 = @import("recursion_air_composition_circuit_v3_write_inputs_from_validated_profile_and_policy.zig");

const std = dependency_0.std;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const m31 = dependency_0.m31;
const Sha256 = dependency_0.Sha256;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const segment_manifest_mod = dependency_0.segment_manifest_mod;
const universal_manifest_mod = dependency_0.universal_manifest_mod;
const temporal_pair_node = dependency_0.temporal_pair_node;
const authority_mint = dependency_0.authority_mint;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const ORDERED_PROGRAM_DOMAIN = dependency_0.ORDERED_PROGRAM_DOMAIN;
const CLAIM_INPUT_CONTENT_DOMAIN = dependency_0.CLAIM_INPUT_CONTENT_DOMAIN;
const CANONICAL_EMPTY_AIR_ID_DOMAIN = dependency_0.CANONICAL_EMPTY_AIR_ID_DOMAIN;
const ProofKind = dependency_0.ProofKind;
const AirProgramId = dependency_0.AirProgramId;
const UNIVERSAL_PHYSICAL_CLAIM_COUNT = dependency_0.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const EMPTY_PHYSICAL_CLAIM_COUNT = dependency_0.EMPTY_PHYSICAL_CLAIM_COUNT;
const MAX_PHYSICAL_CLAIM_COUNT = dependency_0.MAX_PHYSICAL_CLAIM_COUNT;
const POSEIDON_PARTIAL_COUNT = dependency_0.POSEIDON_PARTIAL_COUNT;
const POSEIDON_ROSTER_ROW = dependency_0.POSEIDON_ROSTER_ROW;
const POSEIDON_AUX_START = dependency_0.POSEIDON_AUX_START;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const RELATION_CHALLENGE_COUNT = dependency_0.RELATION_CHALLENGE_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT = dependency_0.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT;
const HEAP_ALLOCATIONS_PER_CLAIM_WRITE = dependency_0.HEAP_ALLOCATIONS_PER_CLAIM_WRITE;
const HEAP_ALLOCATIONS_PER_INPUT_WRITE = dependency_0.HEAP_ALLOCATIONS_PER_INPUT_WRITE;
const HEAP_ALLOCATIONS_PER_AUTHORITY_MINT = dependency_0.HEAP_ALLOCATIONS_PER_AUTHORITY_MINT;
const LEGACY_V2_PROFILE_ACCEPTED = dependency_0.LEGACY_V2_PROFILE_ACCEPTED;
const LOSSY_SEGMENT_PROJECTION_AVAILABLE = dependency_0.LOSSY_SEGMENT_PROJECTION_AVAILABLE;
const PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE = dependency_0.PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE;
const HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE = dependency_0.HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE;
const CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE = dependency_0.CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE;
const HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE = dependency_0.HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE;
const RECORDER_MINT_SUBSTRATE_AVAILABLE = dependency_0.RECORDER_MINT_SUBSTRATE_AVAILABLE;
const HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE = dependency_0.HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE;
const CIRCUIT_AUTHORITY_MINT_AVAILABLE = dependency_0.CIRCUIT_AUTHORITY_MINT_AVAILABLE;
const Error = dependency_0.Error;
const ManifestFamilyV3 = dependency_0.ManifestFamilyV3;
const proofKindIndex = dependency_0.proofKindIndex;
const proofKindCode = dependency_0.proofKindCode;
const ConfigurationV3 = dependency_1.ConfigurationV3;
const CircuitAuthorityV3 = dependency_1.CircuitAuthorityV3;
const CircuitAuthorityStorageV3 = dependency_2.CircuitAuthorityStorageV3;
const CircuitViewV3 = dependency_2.CircuitViewV3;
const circuitAuthorityIdentity = dependency_2.circuitAuthorityIdentity;
const RecordedHeterogeneousCircuitV3 = dependency_3.RecordedHeterogeneousCircuitV3;
const RecordedHeterogeneousCircuitStorageV3 = dependency_4.RecordedHeterogeneousCircuitStorageV3;
const validateClaimInputs = dependency_4.validateClaimInputs;

pub fn validateGraphBindings(
    configuration: ConfigurationV3,
    graph: graph_mod.CircuitGraph,
    bindings: []const graph_mod.RecursionInputBinding,
) Error!void {
    try graph.validate();
    const profile = configuration.graphInputProfile();
    const expected_count = try graph_mod.recursionInputCount(profile);
    if (bindings.len != expected_count)
        return error.CircuitAuthorityMismatch;
    var binding_cursor: usize = 0;
    for (graph.nodes, 0..) |node, node_id| switch (node.op) {
        .input => {
            if (binding_cursor >= bindings.len)
                return error.CircuitAuthorityMismatch;
            const binding = bindings[binding_cursor];
            const source = graph_mod.expectedRecursionSource(
                profile,
                binding_cursor,
            ) orelse return error.CircuitAuthorityMismatch;
            if (binding.node_id != node_id or !std.meta.eql(binding.source, source))
                return error.CircuitAuthorityMismatch;
            binding_cursor += 1;
        },
        else => {},
    };
    if (binding_cursor != bindings.len)
        return error.CircuitAuthorityMismatch;
}

pub fn segmentOrderedProgramIdentity(
    manifest: *const segment_manifest_mod.Manifest,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ORDERED_PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u8, @intFromEnum(ManifestFamilyV3.segment_v2));
    const program_geometry_id =
        segment_manifest_mod.programGeometryShaId(manifest);
    hash.update(&program_geometry_id);
    hash.update(&manifest.catalog_identity);
    hashManifestRows(&hash, manifest);
    return hash.finalResult();
}

pub fn universalOrderedProgramIdentity(
    manifest: *const universal_manifest_mod.Manifest,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ORDERED_PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u8, @intFromEnum(ManifestFamilyV3.universal_v1));
    hash.update(&manifest.seal);
    hashManifestRows(&hash, manifest);
    return hash.finalResult();
}

pub fn hashManifestRows(hash: *Sha256, manifest: anytype) void {
    hashInt(hash, u8, manifest.roster_count);
    for (manifest.roster_rows[0..manifest.roster_count], 0..) |row, ordinal| {
        const placement = manifest.placements[row].?;
        hashInt(hash, u8, @intCast(ordinal));
        hashInt(hash, u8, row);
        hashInt(hash, u8, placement.claimed_sum_index);
        hashInt(hash, u32, placement.geometry.log_size);
        hashInt(hash, u16, placement.geometry.preprocessed_columns);
        hashInt(hash, u16, placement.geometry.main_columns);
        hashInt(hash, u16, placement.geometry.interaction_columns);
        hashInt(hash, u16, placement.geometry.direct_constraints);
        hashInt(hash, u16, placement.geometry.interaction_batches);
        hashInt(hash, u8, placement.geometry.protocol_constraint_degree);
        hashInt(hash, u8, placement.geometry.profiled_constraint_degree);
        hash.update(&placement.geometry.semantic_digest);
    }
}

pub fn validateCanonicalEmptyPublication(
    child: *const temporal_pair_node.VerifiedChildV2,
) Error!void {
    const statement = child.statement() catch
        return error.CanonicalEmptyProgramMismatch;
    if (child.kind != .empty_leaf or
        child.scope != .protocol_padding or
        child.proof_present or
        child.roster_count != 0 or
        statement.slots.height != 0 or
        child.position != (temporal_pair_node.positionForNextParent(statement) catch
            return error.CanonicalEmptyProgramMismatch))
    {
        return error.CanonicalEmptyProgramMismatch;
    }
    switch (statement.body) {
        .empty => {},
        .executed => return error.CanonicalEmptyProgramMismatch,
    }
    try requireAirProgramId(child.session_id);
    try requireAirProgramId(child.job_id);
    try requireAirProgramId(child.recursive_parent_vk_id);
    const expected_job = temporal_pair_node.jobId(&child.statement_words) catch
        return error.CanonicalEmptyProgramMismatch;
    if (!std.meta.eql(expected_job, child.job_id))
        return error.CanonicalEmptyProgramMismatch;
    inline for (.{
        child.verification_key_id,
        child.air_program_id,
        child.manifest_id,
        child.profile_id,
        child.proof_id,
        child.transcript_id,
        child.capture_id,
        child.verifier_receipt_id,
        child.claimed_sums_id,
        child.relation_replay_id,
        child.auxiliary_claim_seal_id,
        child.closure_receipt_id,
        child.lineage_id,
    }) |digest| if (!allZeroU32(&digest))
        return error.CanonicalEmptyProgramMismatch;
    for (child.closure_value) |word| if (word != 0)
        return error.CanonicalEmptyProgramMismatch;
}

pub fn canonicalEmptyAirProgramId(identity: *const [32]u8) AirProgramId {
    var hash = Sha256.init(.{});
    hash.update(CANONICAL_EMPTY_AIR_ID_DOMAIN);
    hash.update(identity);
    const digest = hash.finalResult();
    var result: AirProgramId = undefined;
    for (&result, 0..) |*word, index| {
        const raw = std.mem.readInt(
            u32,
            digest[4 * index ..][0..4],
            .little,
        );
        word.* = raw % m31.Modulus;
    }
    if (allZeroU32(&result)) result[0] = 1;
    return result;
}

pub fn allZeroU32(values: []const u32) bool {
    var aggregate: u32 = 0;
    for (values) |word| aggregate |= word;
    return aggregate == 0;
}

/// Private mint seam, reached only after finalized-recording validation.
pub fn mintCircuitAuthorityFromValidatedRecording(
    recording: *const RecordedHeterogeneousCircuitStorageV3,
) Error!CircuitAuthorityStorageV3 {
    return authority_mint.mint(
        CircuitAuthorityStorageV3,
        recording,
        circuitAuthorityIdentity,
    );
}

pub fn authorityHandle(
    storage: *const CircuitAuthorityStorageV3,
) *const CircuitAuthorityV3 {
    return @ptrCast(storage);
}

/// Non-authoritative content digest for diagnostics and mutation detection.
/// It deliberately does not identify a circuit configuration or AIR program;
/// protocol publications must bind this content under their trusted
/// `ConfigurationV3.identity` instead of using this digest alone.
pub fn claimInputContentDigest(
    proof_kind: ProofKind,
    values: *const [COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) Error![32]u8 {
    try validateClaimInputs(proof_kind, values);
    var hash = Sha256.init(.{});
    hash.update(CLAIM_INPUT_CONTENT_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, proofKindCode(proof_kind));
    hashInt(&hash, u8, COMPOSITION_CLAIM_INPUT_COUNT);
    for (values) |value| for (value.toM31Array()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

pub fn requireAirProgramId(value: AirProgramId) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.AirProgramIdentityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.AirProgramIdentityMismatch;
}

pub fn requireCanonicalM31(value: M31) Error!void {
    if (value.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

pub fn requireCanonicalQm31(value: QM31) Error!void {
    for (value.toM31Array()) |word| try requireCanonicalM31(word);
}

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

pub fn allZero(value: []const u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 2 or
        UNIVERSAL_PHYSICAL_CLAIM_COUNT != 36 or
        SEGMENT_PHYSICAL_CLAIM_COUNT != 39 or
        EMPTY_PHYSICAL_CLAIM_COUNT != 0 or
        MAX_PHYSICAL_CLAIM_COUNT != 39 or
        POSEIDON_PARTIAL_COUNT != 2 or POSEIDON_ROSTER_ROW != 34 or
        POSEIDON_AUX_START != 39 or COMPOSITION_CLAIM_INPUT_COUNT != 41 or
        RELATION_CHALLENGE_COUNT != 47 or PROGRAM_KIND_COUNT != 3 or
        CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT != 45 or
        LEGACY_V2_PROFILE_ACCEPTED or LOSSY_SEGMENT_PROJECTION_AVAILABLE or
        !PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE or
        !HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE or
        !CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE or
        !HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE or
        !RECORDER_MINT_SUBSTRATE_AVAILABLE or
        HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE or
        CIRCUIT_AUTHORITY_MINT_AVAILABLE or
        HEAP_ALLOCATIONS_PER_CLAIM_WRITE != 0 or
        HEAP_ALLOCATIONS_PER_INPUT_WRITE != 0 or
        HEAP_ALLOCATIONS_PER_AUTHORITY_MINT != 0)
    {
        @compileError("V3 recursion composition authority geometry drifted");
    }
    if (@intFromEnum(ProofKind.segment_leaf) != proofKindIndex(.segment_leaf) or
        @intFromEnum(ProofKind.binary_node) != proofKindIndex(.binary_node) or
        @intFromEnum(ProofKind.empty_leaf) != proofKindIndex(.empty_leaf))
    {
        @compileError("upstream recursion proof-kind encoding drifted");
    }
    switch (@typeInfo(CircuitAuthorityV3)) {
        .@"opaque" => {},
        else => @compileError("V3 circuit authority must remain opaque"),
    }
    switch (@typeInfo(CircuitViewV3)) {
        .@"opaque" => {},
        else => @compileError("V3 circuit view must remain opaque"),
    }
    switch (@typeInfo(RecordedHeterogeneousCircuitV3)) {
        .@"opaque" => {},
        else => @compileError("V3 finalized recording must remain opaque"),
    }
}

test "V3 recorder authority seal rejects graph configuration and binding mutations" {
    const allocator = std.testing.allocator;
    var configuration = ConfigurationV3{
        .sampled_value_count = 0,
        // The private authority primitive deliberately consumes only an
        // already-validated configuration identity and input profile.  The
        // complete finalized-session path validates the roster before minting.
        .program_roster = undefined,
        .identity = [_]u8{0x4d} ** 32,
    };
    const profile = configuration.graphInputProfile();
    const input_count = try graph_mod.recursionInputCount(profile);

    const bindings = try allocator.alloc(
        graph_mod.RecursionInputBinding,
        input_count,
    );
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(input_count, 1);
    var first_input: recorder.Scalar = undefined;
    for (bindings, 0..) |*binding, index| {
        const input = try builder.input();
        if (index == 0) first_input = input.value;
        binding.* = .{
            .node_id = input.node_id,
            .source = graph_mod.expectedRecursionSource(
                profile,
                index,
            ) orelse return error.CircuitAuthorityMismatch,
        };
    }
    try builder.activate();
    try builder.constrainZero(first_input);
    builder.deactivate();
    var graph = try builder.finish();

    var recording = RecordedHeterogeneousCircuitStorageV3{
        .allocator = allocator,
        .recorded = graph,
        .bindings = bindings,
        .configuration = configuration,
        .sample_input_authority = undefined,
        .statistics = undefined,
        .authority = undefined,
    };
    defer recording.deinitOwned();
    graph = undefined;
    recording.authority = try mintCircuitAuthorityFromValidatedRecording(
        &recording,
    );
    const public_authority = authorityHandle(&recording.authority);
    try std.testing.expectEqualDeep(
        recording.authority.identity,
        public_authority.identity(),
    );
    try recording.authority.validateAgainstValidatedConfiguration(
        configuration,
        recording.graph(),
        recording.bindings,
    );

    inline for (.{ "configuration_identity", "graph_identity", "identity" }) |
        field_name,
    | {
        var mutation = recording.authority;
        @field(mutation, field_name)[0] ^= 1;
        try std.testing.expectError(
            error.CircuitAuthorityMismatch,
            mutation.validateAgainstValidatedConfiguration(
                configuration,
                recording.graph(),
                recording.bindings,
            ),
        );
    }

    var mutation = recording.authority;
    mutation.format_version +%= 1;
    try std.testing.expectError(
        error.CircuitAuthorityMismatch,
        mutation.validateAgainstValidatedConfiguration(
            configuration,
            recording.graph(),
            recording.bindings,
        ),
    );
    mutation = recording.authority;
    mutation.schema_version +%= 1;
    try std.testing.expectError(
        error.CircuitAuthorityMismatch,
        mutation.validateAgainstValidatedConfiguration(
            configuration,
            recording.graph(),
            recording.bindings,
        ),
    );
    mutation = recording.authority;
    mutation.binding_count -= 1;
    try std.testing.expectError(
        error.CircuitAuthorityMismatch,
        mutation.validateAgainstValidatedConfiguration(
            configuration,
            recording.graph(),
            recording.bindings,
        ),
    );

    configuration.identity[0] ^= 1;
    try std.testing.expectError(
        error.CircuitAuthorityMismatch,
        recording.authority.validateAgainstValidatedConfiguration(
            configuration,
            recording.graph(),
            recording.bindings,
        ),
    );
    configuration.identity[0] ^= 1;

    recording.bindings[0].node_id += 1;
    try std.testing.expectError(
        error.CircuitAuthorityMismatch,
        recording.authority.validateAgainstValidatedConfiguration(
            configuration,
            recording.graph(),
            recording.bindings,
        ),
    );
}
