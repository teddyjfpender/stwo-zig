//! Produce the tiny detached transcript using the existing admitted SegmentV2
//! witness and AIR writers. A returned candidate is not a verification receipt.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const postcard = @import("interop_postcard");
const cohort_mod = @import("recursive_segment_v2_outer_cohort.zig");
const leaf = @import("recursive_segment_v2_leaf_outer.zig");
const transcript = @import("recursive_segment_v2_detached_transcript.zig");
const verifier = @import("recursive_segment_v2_detached_verifier.zig");
const storage = @import("stwo_riscv_frontend").recursion.transaction_storage_v2;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const stage_profile = @import("stwo_prover_api").stage_profile;
const native_preprocessed = frontend.prover_mod.preprocessed;
const recording = recursion.recording_poseidon_channel_v4;
const transcript_equivalence = recursion.transcript_equivalence_v2;
pub const CpuEngine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
pub const Profile = transcript.ProfileV1;

pub const Candidate = struct {
    allocator: std.mem.Allocator,
    key_json: []u8,
    proof_bytes: []u8,
    claims: verifier.ClaimsV1,
    circuit_identity: [32]u8,
    transcript_recording_sha256: ?[32]u8 = null,
    prepare_ns: u64,
    prove_ns: u64,

    pub fn deinit(self: *Candidate) void {
        self.allocator.free(self.proof_bytes);
        self.allocator.free(self.key_json);
        self.* = undefined;
    }
};

/// Opt-in retained candidate alongside the existing complete-proof parity
/// oracle. A separate verifier process must accept the artifact after this
/// process exits. Environment variables select local development artifacts,
/// never change protocol parameters or grant verification authority.
pub fn retainIfRequested(allocator: std.mem.Allocator, prepared: *const leaf.PreparedNativeV2LeafOuter) !void {
    const directory = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_DETACHED_OUTPUT") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(directory);
    const command = @import("recursive_segment_v2_detached_command.zig");
    const key_path = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_DETACHED_KEY") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (key_path) |path| allocator.free(path);
    const key_pin = std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_DETACHED_KEY_SHA256") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (key_pin) |pin| allocator.free(pin);
    if ((key_path == null) != (key_pin == null)) return error.MissingDetachedKeyAdmission;
    var owned_key: ?*command.OwnedKeyV1 = null;
    defer if (owned_key) |key| key.deinit();
    if (key_path) |path| {
        var pin: [32]u8 = undefined;
        if (key_pin.?.len != 64) return error.InvalidDetachedKeyPin;
        _ = try std.fmt.hexToBytes(&pin, key_pin.?);
        const bytes = try std.fs.cwd().readFileAlloc(allocator, path, command.MAX_KEY_BYTES);
        defer allocator.free(bytes);
        owned_key = try command.OwnedKeyV1.admitWithNativeRoot(CpuEngine, allocator, bytes, pin);
    }
    var candidate = try produce(allocator, prepared, if (owned_key) |key| key.key() else null);
    defer candidate.deinit();
    const hashes = try command.retainCandidate(allocator, directory, candidate.key_json, candidate.claims, candidate.proof_bytes);
    // This expected statement is a producer-side convenience. The verifier
    // command receives an explicit caller-selected expected-wire path.
    const expected_json = try command.encodeExpected(allocator, &prepared.capture.public_data.data);
    defer allocator.free(expected_json);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    var expected_file = try dir.createFile("expected-wire.json", .{ .exclusive = true });
    defer expected_file.close();
    try expected_file.writeAll(expected_json);
    std.debug.print("SEGMENT_V2_DETACHED_CANDIDATE directory={s} circuit_identity={s} key_sha256={s} proof_sha256={s} proof_bytes={d} reused_admitted_key={} prepare_ns={d} prove_ns={d} status=unverified\n", .{
        directory, std.fmt.bytesToHex(candidate.circuit_identity, .lower), std.fmt.bytesToHex(hashes.key_sha256, .lower), std.fmt.bytesToHex(hashes.proof_sha256, .lower), hashes.proof_bytes, owned_key != null, candidate.prepare_ns, candidate.prove_ns,
    });
}

/// If an independently admitted key is supplied, require the exact same fixed
/// projection, including Tree0 and every lowering anchor. Matching dimensions
/// alone cannot admit a changed circuit. Without a supplied key this exports a
/// candidate for admission; it does not self-authorize a verifier.
pub fn produce(
    allocator: std.mem.Allocator,
    prepared: *const leaf.PreparedNativeV2LeafOuter,
    admitted_key: ?*const verifier.KeyV1,
) !Candidate {
    return produceWithProfile(allocator, prepared, admitted_key, .development_q3_v1);
}

pub fn produceWithProfile(allocator: std.mem.Allocator, prepared: *const leaf.PreparedNativeV2LeafOuter, admitted_key: ?*const verifier.KeyV1, profile: Profile) !Candidate {
    return produceWithEngine(CpuEngine, allocator, prepared, admitted_key, profile);
}

pub fn produceWithEngine(comptime Engine: type, allocator: std.mem.Allocator, prepared: *const leaf.PreparedNativeV2LeafOuter, admitted_key: ?*const verifier.KeyV1, profile: Profile) !Candidate {
    const TreeStorage = storage.TreeStorageFor(Engine);
    try requireNativeProfile(prepared, profile);
    if (admitted_key) |key| {
        if (key.profile != profile) return error.InvalidSegmentDetachedProfile;
        try key.validateExpectedLayout(&prepared.capture.public_data.data);
        if (!std.meta.eql(key.native_preprocessed_root, prepared.admitted_native_tree0_root))
            return error.InvalidNativePreprocessedCommitment;
    }
    var timer = try std.time.Timer.start();
    var recorder = stage_profile.Recorder.initWithOptions(allocator, if (Engine.Backend == CpuEngine.Backend) "cpu" else "device", "detached-recursive-wrapper", .{ .capture_tasks = false });
    defer recorder.deinit();
    const diagnostic: ?*stage_profile.Recorder = if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_WRAPPER_PROFILE")) &recorder else null;
    var phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.cohort", "Admitted wrapper cohort");
    defer phase.end();
    var cohort = try cohort_mod.Cohort.init(allocator, prepared);
    defer cohort.deinit();
    phase.end();
    const manifest = cohort.manifest();
    std.debug.print("SEGMENT_V2_DETACHED_GEOMETRY profile={s} cohort_ns={d} poseidon_calls={d} tree0_evaluation_bytes={d} tree1_evaluation_bytes={d} tree2_evaluation_bytes={d} excludes=pcs_expansion_commitments_and_metadata before_tree_allocation=true\n", .{
        @tagName(profile),                            timer.read(),                                 cohort.core.poseidonCallCount(),
        try TreeStorage.evaluationBytes(manifest, 0), try TreeStorage.evaluationBytes(manifest, 1), try TreeStorage.evaluationBytes(manifest, 2),
    });
    var scheme = try Engine.init(allocator, profile.pcsConfig());
    // CPU reuses commitment coefficients for sampled openings; PCS releases
    // them after evaluation. Metal already evaluates the committed columns on
    // device: retention measured no speedup and increased peak RSS. This local
    // storage choice changes neither admission nor the serialized proof.
    scheme.setCoefficientRetentionPolicy(if (Engine.Backend == CpuEngine.Backend) .always else .never);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel: Engine.Channel = if (comptime Engine.Channel == recording.Channel)
        recording.Channel.init(allocator)
    else
        .{};
    defer if (comptime Engine.Channel == recording.Channel) channel.deinit();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.fixed", "Fixed columns and key admission");
    var preprocessed = try TreeStorage.init(allocator, manifest, 0);
    defer preprocessed.deinit();
    const fixed_root = try commitFixedColumns(Engine, allocator, &cohort, &preprocessed, &scheme, &channel, null);
    var wire_terms: std.ArrayList(recursion.air.verifier_arithmetic_lowering.PublicWireTerm) = .empty;
    defer wire_terms.deinit(allocator);
    var candidate_key = try fixedKey(allocator, prepared, &cohort, profile, fixed_root, &wire_terms);
    defer candidate_key.native_sum_topology.?.deinit(allocator);
    const identity = try candidate_key.identity();
    const key = admitted_key orelse &candidate_key;
    if (!std.meta.eql(identity, try key.identity()))
        return error.SegmentDetachedFixedCircuitMismatch;
    const key_json = try std.json.Stringify.valueAlloc(allocator, key.*, .{});
    errdefer allocator.free(key_json);
    const prepare_ns = timer.lap();
    phase.end();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.main_fill", "Main column allocation and filling");
    var main = try TreeStorage.init(allocator, manifest, 1);
    defer main.deinit();
    try cohort.fillMainInto(manifest, main.columns);
    phase.end();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.main_commit", "Main commitment");
    try main.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    phase.end();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.interaction_fill", "Interaction transcript and filling");
    const expected = &prepared.capture.public_data.data;
    try transcript.mixAdmission(&channel, key, expected);
    const interaction_pow: ?u64 = if (profile.interactionPowBits() == 0) null else try @import("stwo_prover_engine").pcs.proof_of_work.grindForBackend(Engine.Backend, &channel, profile.interactionPowBits());
    try transcript.mixInteractionPow(&channel, key, interaction_pow);
    const relations = try recursion.air.universal_challenges.UniversalRelations.draw(allocator, &channel);
    const providers = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    var interaction = try TreeStorage.init(allocator, manifest, 2);
    defer interaction.deinit();
    const generator = try recursion.leaf_interaction_generator_v2.ForBackend(Engine.Backend).init(allocator, key.parameters, manifest);
    const device_capable = comptime @hasDecl(Engine.Backend, "supportsFrameworkInteractions");
    const dispatches_before = if (device_capable) (try Engine.Backend.telemetrySnapshot()).counters.metal_framework_interaction_dispatches else 0;
    const generated = try cohort.fillInteractionIntoWithGenerator(manifest, &relations, &providers, interaction.columns, &generator);
    if (comptime device_capable) {
        if (generator.device) {
            const dispatches = (try Engine.Backend.telemetrySnapshot()).counters.metal_framework_interaction_dispatches - dispatches_before;
            // Row 10 remains the authenticated inactive zero-column fast path.
            const components = recursion.air.segment_leaf_catalog_v2.LOGICAL_ROWS.len - 1;
            if (dispatches != components * 4) return error.LeafTypedInteractionDispatchMissing;
            std.debug.print("DETACHED_LEAF_TYPED_DEVICE_INTERACTION components={d} inactive_zero_components=1 dispatches={d}\n", .{ components, dispatches });
        }
    }
    var claim_vector = try cohort.claimVector(&generated);
    phase.end();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.closure", "Global lookup closure");
    _ = try cohort.auditGlobalClosure(&generated, &claim_vector, &relations, &providers);
    phase.end();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.interaction_commit", "Interaction transcript and commitment");
    const claims = verifier.ClaimsV1{ .values = claim_vector.values, .poseidon_partials = generated.core.poseidon2_partials, .interaction_pow = interaction_pow };
    try transcript.mixClaimsAndBoundary(&channel, key, expected, claims, &relations);
    try interaction.commit(&scheme, &channel);
    phase.end();
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.components", "Typed component assembly");
    var components = try cohort.initComponents(&generated, &relations, &providers);
    defer components.deinit();
    var gate = try manifest_mod.ProofGate.init(manifest);
    try components.appendToGate(manifest, &gate);
    try gate.sealGate(manifest);
    phase.end();
    scheme_moved = true;
    var extended = try Engine.prove(allocator, try gate.proverSlice(), &channel, scheme, .{ .recorder = diagnostic });
    defer extended.deinit(allocator);
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.serialize", "Canonical proof serialization");
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try postcard.serializeProof(recursion.engine.Hasher, encoded.writer(allocator), extended.proof);
    if (encoded.items.len == 0 or encoded.items.len > verifier.MAX_PROOF_BYTES)
        return error.SegmentDetachedProofSizeMismatch;
    var transcript_recording_sha256: ?[32]u8 = null;
    if (comptime Engine.Channel == recording.Channel) {
        var producer_execution = try channel.finish();
        defer producer_execution.deinit();
        var verifier_channel = recording.Channel.init(allocator);
        defer verifier_channel.deinit();
        _ = try recursion.detached_segment_verifier_v1.verifyWithChannel(
            recording.MerkleChannel,
            allocator,
            key,
            expected,
            claims,
            encoded.items,
            &verifier_channel,
            null,
        );
        var verifier_execution = try verifier_channel.finish();
        defer verifier_execution.deinit();
        try transcript_equivalence.compareRecordings(&producer_execution, &verifier_execution);
        transcript_recording_sha256 = producer_execution.identity_sha256;
        std.debug.print("DETACHED_LEAF_TRANSCRIPT_EQUIVALENCE proof_bytes={d} operations={d} frames={d} calls={d} identity={s}\n", .{
            encoded.items.len,
            producer_execution.operations.len,
            producer_execution.hash_frames.len,
            producer_execution.poseidon_calls.len,
            std.fmt.bytesToHex(producer_execution.identity_sha256, .lower),
        });
    }
    phase.end();
    const prove_ns = timer.read();
    if (diagnostic != null) {
        var snapshot = try recorder.snapshot(allocator);
        defer snapshot.deinit(allocator);
        const json = try std.json.Stringify.valueAlloc(allocator, snapshot, .{});
        defer allocator.free(json);
        std.debug.print("DETACHED_WRAPPER_STAGE_PROFILE {s}\n", .{json});
    }
    return .{
        .allocator = allocator,
        .key_json = key_json,
        .proof_bytes = try encoded.toOwnedSlice(allocator),
        .claims = claims,
        .circuit_identity = identity,
        .transcript_recording_sha256 = transcript_recording_sha256,
        .prepare_ns = prepare_ns,
        .prove_ns = prove_ns,
    };
}

fn requireNativeProfile(prepared: *const leaf.PreparedNativeV2LeafOuter, profile: Profile) !void {
    // A stronger outer proof cannot repair a weak native child. This check is
    // before cohort allocation, and the resulting fixed AIR is independently
    // admitted through the same pinned-key transaction as development.
    if (profile == .recursive_q193_v1 and
        (!std.meta.eql(prepared.pcs_config, recursion.protocol.PCS_CONFIG) or
            prepared.captured_fri.interaction_pow_bits != recursion.protocol.INTERACTION_POW_BITS))
        return error.DetachedNativeSecurityProfileMismatch;
}

fn commitFixedColumns(comptime Engine: type, allocator: std.mem.Allocator, cohort: *cohort_mod.Cohort, preprocessed: *storage.TreeStorageFor(Engine), scheme: anytype, channel: *Engine.Channel, key_row_digests: ?*[6][32]u8) !recursion.poseidon2_channel.Digest {
    const manifest = cohort.manifest();
    try cohort.fillPreprocessedInto(manifest, preprocessed.columns);
    if (key_row_digests) |digests| digests.* = keyRowDigests(manifest, preprocessed.columns);
    try preprocessed.commit(scheme, channel);
    try Engine.flushPendingCommit(scheme, allocator, channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1) return error.SegmentDetachedPreprocessedCommitmentMismatch;
    return roots.items[0];
}

fn fixedKey(allocator: std.mem.Allocator, prepared: *const leaf.PreparedNativeV2LeafOuter, cohort: *const cohort_mod.Cohort, profile: Profile, fixed_root: recursion.poseidon2_channel.Digest, wire_terms: *std.ArrayList(recursion.air.verifier_arithmetic_lowering.PublicWireTerm)) !verifier.KeyV1 {
    if (prepared.capture.proof.commitments.len == 0) return error.InvalidNativePreprocessedCommitment;
    const authenticated_wire = try prepared.capture.public_data.data.authenticatedView();
    const retained_layout = try recursion.segment_statement_v2_transcript_layout.Layout.fromView(&authenticated_wire);
    var topology = try recursion.segment_public_native_sum_topology_v1.Topology.fromView(
        allocator,
        &authenticated_wire,
    );
    errdefer topology.deinit(allocator);
    var native_sum_graph = try recursion.segment_public_native_sum_authority_v2.buildNativeGraphFromTopology(
        allocator,
        &retained_layout,
        topology,
    );
    defer native_sum_graph.circuit.deinit();
    var native_sum_owned = try recursion.segment_public_native_sum_authority_v2.NativeOwnedGraph.init(
        allocator,
        &native_sum_graph.circuit,
    );
    defer native_sum_owned.deinit();
    if (!std.meta.eql(
        native_sum_owned.graph.identity_digest,
        cohort.public_native_sum_source.loweringLane().graph.identity_digest,
    )) return error.PublicNativeSumKeyGraphMismatch;
    std.debug.assert(wire_terms.items.len == 0);
    for (cohort.core.authority.lowering_plan.public_terms) |term|
        if (term.active_in == .segment) try wire_terms.append(allocator, term);
    return verifier.KeyV1{
        .profile = profile,
        .pcs_config = profile.pcsConfig(),
        .manifest = cohort.manifest().*,
        .preprocessed_root = fixed_root,
        .native_preprocessed_root = prepared.admitted_native_tree0_root,
        .parameters = .{
            .query_reference = cohort.core.authority.query_bits_reference,
            .poseidon_active_rows = std.math.cast(u32, cohort.core.poseidonCallCount()) orelse return error.ArithmeticOverflow,
        },
        .source_manifest = prepared.authority_prepared.source.manifest,
        .retained_section_counts = retained_layout.counts,
        .native_sum_topology = topology,
        .admitted_keys = prepared.authority_prepared.source.verifier_keys,
        .native_descriptors = .{ .components = prepared.capture.vm_air.component_descs, .infrastructure = prepared.capture.vm_air.infra_descs },
        .wire_terms = wire_terms.items,
    };
}

/// Setup commits only fixed columns and emits key bytes. It creates no outer
/// proof or main/interaction trace; subsequent production takes an independent pin.
/// Prepared native inputs and compiler policy remain caller admission obligations.
pub fn deriveKey(allocator: std.mem.Allocator, prepared: *const leaf.PreparedNativeV2LeafOuter, profile: Profile) ![]u8 {
    try requireNativeProfile(prepared, profile);
    if (prepared.capture.proof.commitments.len == 0) return error.InvalidNativePreprocessedCommitment;
    const native_root = try native_preprocessed.rootForDescriptors(
        CpuEngine,
        allocator,
        profile.nativePcsConfig(),
        prepared.capture.vm_air.component_descs,
        prepared.capture.vm_air.infra_descs,
    );
    if (!std.meta.eql(native_root, prepared.capture.proof.commitments[0]))
        return error.InvalidNativePreprocessedCommitment;
    var cohort = try cohort_mod.Cohort.init(allocator, prepared);
    defer cohort.deinit();
    var scheme = try CpuEngine.init(allocator, profile.pcsConfig());
    defer CpuEngine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = CpuEngine.Channel{};
    var preprocessed = try storage.TreeStorageFor(CpuEngine).init(allocator, cohort.manifest(), 0);
    defer preprocessed.deinit();
    var key_row_digests: [6][32]u8 = undefined;
    const root = try commitFixedColumns(CpuEngine, allocator, &cohort, &preprocessed, &scheme, &channel, &key_row_digests);
    var wire_terms: std.ArrayList(recursion.air.verifier_arithmetic_lowering.PublicWireTerm) = .empty;
    defer wire_terms.deinit(allocator);
    var key = try fixedKey(allocator, prepared, &cohort, profile, root, &wire_terms);
    defer key.native_sum_topology.?.deinit(allocator);
    try key.validate();
    if (profile == .recursive_q193_v1) try recursion.detached_fixed_tree0_arithmetic_recipe_v1.validateAgainstProduction(
        allocator,
        &key,
        &cohort.core.authority.lowering_plan,
    );
    if (profile == .recursive_q193_v1) try validateKeyFixedColumns(
        allocator,
        &key,
        key_row_digests,
    );
    return std.json.Stringify.valueAlloc(allocator, key, .{});
}

fn validateKeyFixedColumns(
    allocator: std.mem.Allocator,
    key: *const verifier.KeyV1,
    production_digests: [6][32]u8,
) !void {
    const M31 = @import("stwo_core").fields.m31.M31;
    const air = recursion.air;
    const inactive_placement = key.manifest.placements[10] orelse return error.InvalidFixedStatementGeometry;
    const inactive_size = @as(usize, 1) << @intCast(inactive_placement.geometry.log_size);
    const inactive_count = air.statement_input.PREPROCESSED_COLUMN_COUNT;
    const inactive_storage = try allocator.alloc(M31, inactive_size * inactive_count);
    defer allocator.free(inactive_storage);
    var inactive_columns: [inactive_count][]M31 = undefined;
    for (&inactive_columns, 0..) |*column, index|
        column.* = inactive_storage[index * inactive_size ..][0..inactive_size];
    try recursion.detached_fixed_tree0_key_recipe_v1.fillInactiveStatementInputRow(&key.manifest, &inactive_columns);
    const inactive_digest = digestColumnLane(&inactive_columns);
    if (!std.mem.eql(u8, &production_digests[0], &inactive_digest))
        return error.FixedInactiveStatementRowsMismatch;

    const vm_placement = key.manifest.placements[18] orelse return error.InvalidFixedVmInputGeometry;
    const vm_size = @as(usize, 1) << @intCast(vm_placement.geometry.log_size);
    const vm_count = air.vm_air_composition_input_witness.PREPROCESSED_COLUMN_COUNT;
    const vm_storage = try allocator.alloc(M31, vm_size * vm_count);
    defer allocator.free(vm_storage);
    var vm_columns: [vm_count][]M31 = undefined;
    for (&vm_columns, 0..) |*column, index|
        column.* = vm_storage[index * vm_size ..][0..vm_size];
    try recursion.detached_fixed_tree0_vm_input_recipe_v1.fillFromKey(
        allocator,
        key,
        &vm_columns,
    );
    const vm_digest = try digestGeneratedColumnLane(allocator, &vm_columns, vm_placement.geometry.log_size);
    if (!std.mem.eql(u8, &production_digests[1], &vm_digest))
        return error.FixedVmInputRowsMismatch;

    const control_placement = key.manifest.placements[19] orelse return error.InvalidFixedControlGeometry;
    const control_size = @as(usize, 1) << @intCast(control_placement.geometry.log_size);
    const control_count = air.control_slice_witness.COLUMN_COUNT;
    const control_storage = try allocator.alloc(M31, control_size * control_count);
    defer allocator.free(control_storage);
    var control_columns: [control_count][]M31 = undefined;
    for (&control_columns, 0..) |*column, index|
        column.* = control_storage[index * control_size ..][0..control_size];
    try recursion.detached_fixed_tree0_control_recipe_v1.fillFromKey(
        allocator,
        key,
        &control_columns,
    );
    const control_digest = try digestGeneratedColumnLane(allocator, &control_columns, control_placement.geometry.log_size);
    if (!std.mem.eql(u8, &production_digests[2], &control_digest))
        return error.FixedControlRowsMismatch;

    const Counts = .{
        air.qm31_mul_full_witness.PREPROCESSED_COLUMN_COUNT,
        air.qm31_inv_witness.PREPROCESSED_COLUMN_COUNT,
        air.linear_ops_witness.PREPROCESSED_COLUMN_COUNT,
    };
    var generated: [3][]M31 = undefined;
    var views: [3][][]M31 = undefined;
    var initialized: usize = 0;
    defer for (0..initialized) |lane| {
        allocator.free(views[lane]);
        allocator.free(generated[lane]);
    };
    inline for (Counts, 0..) |count, lane| {
        const placement = key.manifest.placements[30 + lane] orelse return error.InvalidFixedArithmeticGeometry;
        const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
        generated[lane] = try allocator.alloc(M31, size * count);
        views[lane] = allocator.alloc([]M31, count) catch |err| {
            allocator.free(generated[lane]);
            return err;
        };
        for (views[lane], 0..) |*column, index|
            column.* = generated[lane][index * size ..][0..size];
        initialized += 1;
    }
    var multiply: [air.qm31_mul_full_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    var inverse: [air.qm31_inv_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    var linear: [air.linear_ops_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    @memcpy(multiply[0..], views[0]);
    @memcpy(inverse[0..], views[1]);
    @memcpy(linear[0..], views[2]);
    try recursion.detached_fixed_tree0_arithmetic_recipe_v1.fillFromKey(
        allocator,
        key,
        &multiply,
        &inverse,
        &linear,
    );
    const rebuilt_digests = [3][32]u8{
        try digestGeneratedColumnLane(allocator, multiply[0..], key.manifest.placements[30].?.geometry.log_size),
        try digestGeneratedColumnLane(allocator, inverse[0..], key.manifest.placements[31].?.geometry.log_size),
        try digestGeneratedColumnLane(allocator, linear[0..], key.manifest.placements[32].?.geometry.log_size),
    };
    inline for (0..3) |lane|
        if (!std.mem.eql(u8, &production_digests[lane + 3], &rebuilt_digests[lane]))
            return error.FixedArithmeticRowsMismatch;
}

fn keyRowDigests(manifest: anytype, columns: anytype) [6][32]u8 {
    const Counts = .{
        recursion.air.qm31_mul_full_witness.PREPROCESSED_COLUMN_COUNT,
        recursion.air.qm31_inv_witness.PREPROCESSED_COLUMN_COUNT,
        recursion.air.linear_ops_witness.PREPROCESSED_COLUMN_COUNT,
    };
    var digests: [6][32]u8 = undefined;
    const inactive_placement = manifest.placements[10].?;
    digests[0] = digestColumnLane(columns[@as(usize, inactive_placement.preprocessed_offset)..][0..recursion.air.statement_input.PREPROCESSED_COLUMN_COUNT]);
    const vm_placement = manifest.placements[18].?;
    digests[1] = digestColumnLane(columns[@as(usize, vm_placement.preprocessed_offset)..][0..recursion.air.vm_air_composition_input_witness.PREPROCESSED_COLUMN_COUNT]);
    const control_placement = manifest.placements[19].?;
    digests[2] = digestColumnLane(columns[@as(usize, control_placement.preprocessed_offset)..][0..recursion.air.control_slice_witness.COLUMN_COUNT]);
    inline for (Counts, 0..) |count, lane| {
        const placement = manifest.placements[30 + lane].?;
        const offset = placement.preprocessed_offset;
        digests[lane + 3] = digestColumnLane(columns[@as(usize, offset)..][0..count]);
    }
    return digests;
}

fn digestColumnLane(columns: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| hash.update(std.mem.sliceAsBytes(column));
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn digestGeneratedColumnLane(allocator: std.mem.Allocator, columns: anytype, log_size: u32) ![32]u8 {
    const M31 = @import("stwo_core").fields.m31.M31;
    const framework = recursion.air.framework_interaction;
    const size = @as(usize, 1) << @intCast(log_size);
    const committed = try allocator.alloc(M31, size);
    defer allocator.free(committed);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |logical| {
        for (logical, 0..) |value, row|
            committed[framework.committedRow(row, log_size)] = value;
        hash.update(std.mem.sliceAsBytes(committed));
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}
