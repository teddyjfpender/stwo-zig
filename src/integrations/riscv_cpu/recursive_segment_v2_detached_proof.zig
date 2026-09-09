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
const storage = @import("recursive_segment_v2_outer_engine_storage.zig");
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const stage_profile = @import("stwo_prover_api").stage_profile;
pub const CpuEngine = recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
pub const Profile = transcript.ProfileV1;

pub const Candidate = struct {
    allocator: std.mem.Allocator,
    key_json: []u8,
    proof_bytes: []u8,
    claims: verifier.ClaimsV1,
    circuit_identity: [32]u8,
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
        owned_key = try command.OwnedKeyV1.admit(allocator, bytes, pin);
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
    // A stronger outer proof cannot repair a weak native child. This check is
    // before cohort allocation, and the resulting fixed AIR is independently
    // admitted through the same pinned-key transaction as development.
    if (profile == .recursive_q193_v1 and
        (!std.meta.eql(prepared.pcs_config, recursion.protocol.PCS_CONFIG) or
            prepared.captured_fri.interaction_pow_bits != recursion.protocol.INTERACTION_POW_BITS))
        return error.DetachedNativeSecurityProfileMismatch;
    if (admitted_key) |key| if (key.profile != profile) return error.InvalidSegmentDetachedProfile;
    var timer = try std.time.Timer.start();
    var recorder = stage_profile.Recorder.initWithOptions(allocator, if (Engine == CpuEngine) "cpu" else "device", "detached-recursive-wrapper", .{ .capture_tasks = false });
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
    scheme.setCoefficientRetentionPolicy(if (Engine == CpuEngine) .always else .never);
    var scheme_moved = false;
    defer if (!scheme_moved) Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    phase = try stage_profile.StageScope.begin(diagnostic, "wrapper.fixed", "Fixed columns and key admission");
    var preprocessed = try TreeStorage.init(allocator, manifest, 0);
    defer preprocessed.deinit();
    try cohort.fillPreprocessedInto(manifest, preprocessed.columns);
    try preprocessed.commit(&scheme, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1) return error.SegmentDetachedPreprocessedCommitmentMismatch;
    var wire_terms: std.ArrayList(recursion.air.verifier_arithmetic_lowering.PublicWireTerm) = .empty;
    defer wire_terms.deinit(allocator);
    for (cohort.core.authority.lowering_plan.public_terms) |term|
        if (term.active_in == .segment) try wire_terms.append(allocator, term);
    const candidate_key = verifier.KeyV1{
        .profile = profile,
        .pcs_config = profile.pcsConfig(),
        .manifest = manifest.*,
        .preprocessed_root = roots.items[0],
        .parameters = .{
            .query_reference = cohort.core.authority.query_bits_reference,
            .poseidon_active_rows = std.math.cast(u32, cohort.core.poseidonCallCount()) orelse return error.ArithmeticOverflow,
        },
        .source_manifest = prepared.authority_prepared.source.manifest,
        .admitted_keys = prepared.authority_prepared.source.verifier_keys,
        .native_descriptors = .{ .components = prepared.capture.vm_air.component_descs, .infrastructure = prepared.capture.vm_air.infra_descs },
        .wire_terms = wire_terms.items,
    };
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
    const interaction_pow: ?u64 = if (profile.interactionPowBits() == 0) null else channel.grind(profile.interactionPowBits());
    try transcript.mixInteractionPow(&channel, key, interaction_pow);
    const relations = try recursion.air.universal_challenges.UniversalRelations.draw(allocator, &channel);
    const providers = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    var interaction = try TreeStorage.init(allocator, manifest, 2);
    defer interaction.deinit();
    const generated = try cohort.fillInteractionInto(manifest, &relations, &providers, interaction.columns);
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
        .prepare_ns = prepare_ns,
        .prove_ns = prove_ns,
    };
}
