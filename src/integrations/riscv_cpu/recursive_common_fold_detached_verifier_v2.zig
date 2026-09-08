//! Common-fold verification from public inputs and an explicit key.
//! Key authenticity is the caller's responsibility: a key supplied alongside
//! an untrusted proof is not an independently admitted circuit. No child
//! proof, witness rows, replay receipt or producer allocation enters verify.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const air = recursion.air;
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const cohort_mod = @import("recursive_common_fold_secure_cohort_v2.zig");
const artifact = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const protocol_mod = @import("recursive_temporal_secure_parent_protocol_v1.zig");
const codec = @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const support = @import("recursive_binary_outer_support.zig");
const public_mod = @import("recursive_field_node_public_v2.zig");
const public_boundary = @import("recursive_common_fold_public_output_v3.zig");
const catalog = manifest_mod.catalog;
const provider = air.universal_shared_provider;
const range = air.range_check_8_8_bridge;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
const Relations = air.universal_challenges.UniversalRelations;
const Scheme = core.pcs.verifier.CommitmentSchemeVerifier(recursion.engine.Hasher, recursion.engine.MerkleChannel);
pub const PRODUCTION_ACTIVATION = false;
pub const ProofCapture = core.pcs.verifier.VerifiedProofCapture(recursion.engine.Hasher);

fn Component(comptime entry: catalog.Entry) type {
    @setEvalBranchQuota(500_000);
    return air.universal_typed_component.ComponentForManifest(entry.Air, air.universal_relation_binding.Binding(entry.Air), manifest_mod);
}
fn Tuple(comptime kind: enum { definition, component, parameters }) type {
    var types: [catalog.LOGICAL_COUNT]type = undefined;
    for (catalog.LOGICAL_ROWS, 0..) |entry, index| types[index] = switch (kind) {
        .definition => entry.Air.Definition,
        .component => Component(entry),
        .parameters => [Component(entry).PARAMETER_COLUMN_COUNT]M31,
    };
    return std.meta.Tuple(&types);
}

/// Public setup data. Validation checks shape, not independent key admission.
pub const Parameters = Tuple(.parameters);
pub const Key = struct {
    manifest: manifest_mod.Manifest,
    preprocessed_root: Digest,
    parameters: Tuple(.parameters),
    poseidon_rows: u32,

    pub fn validate(self: *const Key) !manifest_mod.LogSizes {
        var logs: manifest_mod.LogSizes = undefined;
        for (self.manifest.placements, &logs) |placement, *log|
            log.* = (placement orelse return error.InvalidCommonFoldVerifierKey).geometry.log_size;
        try manifest_mod.validateForDerivedLogSizes(&self.manifest, logs);
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus) return error.InvalidCommonFoldVerifierKey;
        inline for (self.parameters) |parameters| for (parameters) |word|
            if (word.toU32() >= core.fields.m31.Modulus) return error.InvalidCommonFoldVerifierKey;
        if (self.poseidon_rows > (@as(u64, 1) << @intCast(logs[34]))) return error.InvalidCommonFoldVerifierKey;
        return logs;
    }
};

/// Explicit namespace for the Ethereum-child fold circuit. Legacy Key transport
/// and constructors remain byte-for-byte unchanged. A supplied key still needs
/// independent admission; this wrapper is not proof verification evidence.
pub const EthereumKeyV1 = struct {
    version: u32 = 1,
    execution_profile: u32 = 1,
    key: Key,

    pub fn validate(self: *const EthereumKeyV1) !void {
        if (self.version != 1 or self.execution_profile != 1 or std.mem.allEqual(u32, &self.key.preprocessed_root, 0)) return error.InvalidEthereumFoldVerifierKey;
        _ = try self.key.validate();
    }

    pub fn sessionFields(self: *const EthereumKeyV1) !@import("ethereum_wrapper_field_transcript_v1.zig").SessionFieldsV1 {
        try self.validate();
        const fixed = @import("ethereum_wrapper_fixed_circuit_v1.zig");
        const protocol = protocol_mod.AuthorityV1.secureParent();
        var hash = fixed.fixedHeader("stwo-zig/ethereum-fixed-fold-circuit/v1\x00", .{ 1, self.version, 1, manifest_mod.SCHEMA_VERSION, self.execution_profile }, self.key.manifest.seal, protocol, self.key.preprocessed_root);
        inline for (self.key.parameters, 0..) |parameters, index| {
            fixed.word(&hash, index);
            fixed.word(&hash, parameters.len);
            for (parameters) |parameter| fixed.word(&hash, parameter.toU32());
        }
        fixed.word(&hash, self.key.poseidon_rows);
        // Internal fixed anchors are committed by Tree0, including both
        // admitted child roots/keys and each arithmetic graph's constants.
        return fixed.namespaceFromDigest(protocol, hash.finalResult(), .{ 0x4542_564b, 0x4542_4e4b, 0x4542_4150 });
    }

    /// Derive Tree0 from admitted prepared rows, never from proof commitments.
    /// Dynamic child proof/state values do not enter the fixed-key projection.
    pub fn fromPreparedCohort(comptime Cohort: type, allocator: std.mem.Allocator, cohort: *Cohort) !EthereumKeyV1 {
        try cohort.validate();
        const session = try cohort.session();
        const parameters = try cohort.detachedVerifierParameters();
        const root = try codec.derivePreprocessedRoot(Cohort, manifest_mod, allocator, cohort, &session);
        const result = EthereumKeyV1{ .key = .{ .manifest = cohort.manifest().*, .preprocessed_root = root, .parameters = parameters, .poseidon_rows = @intCast(cohort.suffix.providerCallCount()) } };
        try result.validate();
        return result;
    }

    pub fn verify(self: *const EthereumKeyV1, allocator: std.mem.Allocator, node: *const public_mod.NodePublicV2, claims: *const Claims, nonce: u64, proof: []const u8) !Digest {
        return verifyImpl(allocator, &self.key, node, claims, nonce, proof, null, try self.sessionFields());
    }

    pub fn verifyWithCapture(self: *const EthereumKeyV1, allocator: std.mem.Allocator, node: *const public_mod.NodePublicV2, claims: *const Claims, nonce: u64, proof: []const u8, capture: *ProofCapture) !Digest {
        return verifyImpl(allocator, &self.key, node, claims, nonce, proof, capture, try self.sessionFields());
    }
};

pub const Claims = struct {
    values: [manifest_mod.COMPONENT_COUNT]QM31,
    poseidon_partials: [2]QM31,

    fn vector(self: *const Claims, manifest: *const manifest_mod.Manifest) !manifest_mod.ClaimVector {
        var result = try manifest_mod.ClaimVector.init(manifest);
        for (self.values, 0..) |value, index| {
            try canonical(value);
            try result.bind(@enumFromInt(index), value);
        }
        for (self.poseidon_partials) |partial| try canonical(partial);
        if (!self.poseidon_partials[0].add(self.poseidon_partials[1]).eql(self.values[34]))
            return error.InvalidCommonFoldVerifierClaims;
        try result.sealClaims(manifest);
        return result;
    }
};

/// Definitions are rebuilt from the pinned catalog, with no witness storage.
/// Heap allocation keeps component pointers stable throughout verification.
pub const Components = struct {
    allocator: std.mem.Allocator,
    definitions: Tuple(.definition),
    initialized: usize,
    logical: Tuple(.component),
    range_definition: range.Definition,
    range_initialized: bool,
    range_executor: range.Executor,
    poseidon: provider.Poseidon2AdapterForManifest(manifest_mod),
    range_component: provider.RangeCheck8x8AdapterForManifest(manifest_mod),
    gate: manifest_mod.ProofGate,

    pub fn init(allocator: std.mem.Allocator, key: *const Key, claims: *const Claims, relations: *const Relations, providers: *const provider.SharedProviderRelations) !*Components {
        const logs = try key.validate();
        _ = try claims.vector(&key.manifest);
        const gate = try manifest_mod.ProofGate.init(&key.manifest);
        const self = try allocator.create(Components);
        self.* = .{ .allocator = allocator, .definitions = undefined, .initialized = 0, .logical = undefined, .range_definition = undefined, .range_initialized = false, .range_executor = undefined, .poseidon = undefined, .range_component = undefined, .gate = gate };
        errdefer self.deinit();
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            self.definitions[index] = if (entry.requires_location) try entry.Air.build(allocator, .generated) else try entry.Air.build(allocator);
            self.initialized += 1;
            const relation = try air.universal_relation_binding.Binding(entry.Air).authenticate(&self.definitions[index]);
            self.logical[index] = try Component(entry).init(&self.definitions[index], relation, &key.manifest, entry.row, logs[index], key.parameters[index], relations, claims.values[index]);
            try self.gate.append(&key.manifest, try self.logical[index].binding(&key.manifest));
        }
        self.poseidon = try provider.Poseidon2AdapterForManifest(manifest_mod).init(&key.manifest, logs[34], key.poseidon_rows, providers, relations, claims.poseidon_partials);
        try self.gate.append(&key.manifest, try self.poseidon.binding(&key.manifest));
        self.range_definition = try range.build(allocator);
        self.range_initialized = true;
        self.range_executor = try range.Executor.init(&self.range_definition, &try range.Binding.canonical(&self.range_definition));
        self.range_component = try provider.RangeCheck8x8AdapterForManifest(manifest_mod).init(&self.range_definition, &self.range_executor, &key.manifest, providers, relations, claims.values[35]);
        try self.gate.append(&key.manifest, try self.range_component.binding(&key.manifest));
        try self.gate.sealGate(&key.manifest);
        return self;
    }

    pub fn deinit(self: *Components) void {
        inline for (0..catalog.LOGICAL_COUNT) |index| if (index < self.initialized) self.definitions[index].deinit();
        if (self.range_initialized) self.range_definition.deinit();
        self.allocator.destroy(self);
    }
};

pub fn verify(allocator: std.mem.Allocator, key: *const Key, node: *const public_mod.NodePublicV2, claims: *const Claims, interaction_pow_nonce: u64, proof_bytes: []const u8) !Digest {
    return verifyImpl(allocator, key, node, claims, interaction_pow_nonce, proof_bytes, null, null);
}

/// The caller owns capture only after success and must deinit it with allocator.
/// This is the core verifier's actual opening/FRI capture, not supplied geometry.
pub fn verifyWithCapture(allocator: std.mem.Allocator, key: *const Key, node: *const public_mod.NodePublicV2, claims: *const Claims, interaction_pow_nonce: u64, proof_bytes: []const u8, capture: *ProofCapture) !Digest {
    return verifyImpl(allocator, key, node, claims, interaction_pow_nonce, proof_bytes, capture, null);
}

fn verifyImpl(allocator: std.mem.Allocator, key: *const Key, node: *const public_mod.NodePublicV2, claims: *const Claims, interaction_pow_nonce: u64, proof_bytes: []const u8, capture: ?*ProofCapture, field_keys: ?@import("ethereum_wrapper_field_transcript_v1.zig").SessionFieldsV1) !Digest {
    const logs = try key.validate();
    const words = try node.canonicalAirWords();
    const claim_vector = try claims.vector(&key.manifest);
    const protocol = protocol_mod.AuthorityV1.secureParent();
    var proof = try codec.deserializeProtocolProof(allocator, protocol, proof_bytes);
    var proof_owned = true;
    defer if (proof_owned) proof.deinit(allocator);
    const commitments = proof.commitment_scheme_proof.commitments.items;
    if (commitments.len != manifest_mod.TREE_COUNT + 1 or !std.meta.eql(commitments[0], key.preprocessed_root))
        return error.InvalidCommonFoldVerifierKey;
    var scheme = try Scheme.init(allocator, try protocol.pcsConfig());
    defer scheme.deinit(allocator);
    var channel = recursion.poseidon2_channel.Channel{};
    for (0..2) |tree| try support.commitVerifierTreeForManifest(manifest_mod, allocator, &scheme, &key.manifest, tree, commitments[tree], &channel);
    try key.manifest.mixStatementPrefix(&channel);
    channel.mixU32s(&cohort_mod.AUTHORITY_TRANSCRIPT_HEADER);
    channel.mixU32s(&words);
    channel.mixU32s(&try artifact.fieldSessionTranscriptHeader(.common_fold_field_v2, protocol));
    if (field_keys) |keys| {
        channel.mixU32s(&keys.verification_key_id);
        channel.mixU32s(&keys.next_parent_vk_id);
        channel.mixU32s(&keys.air_program_id);
    } else {
        channel.mixU32s(&try manifest_mod.verificationKeyIdForDerivedManifest(&key.manifest, logs));
        channel.mixU32s(&try manifest_mod.nextParentVkIdForDerivedManifest(&key.manifest, logs));
        channel.mixU32s(&try manifest_mod.airProgramIdForDerivedManifest(&key.manifest, logs));
    }
    if (!channel.verifyPowNonce(protocol.interaction_pow_bits, interaction_pow_nonce)) return error.InvalidCommonFoldVerifierPow;
    channel.mixU64(interaction_pow_nonce);
    const relations = try Relations.draw(allocator, &channel);
    const providers = try provider.SharedProviderRelations.init(&relations);
    var total = (try public_boundary.derive(node, &relations)).claimed_sum;
    for (claims.values) |claim| total = total.add(claim);
    if (!total.isZero()) return error.InvalidCommonFoldVerifierClosure;
    try claim_vector.mixInteractionClaimValues(&key.manifest, &channel);
    channel.mixFelts(&claims.poseidon_partials);
    try support.commitVerifierTreeForManifest(manifest_mod, allocator, &scheme, &key.manifest, 2, commitments[2], &channel);
    const components = try Components.init(allocator, key, claims, &relations, &providers);
    defer components.deinit();
    const moved = support.moveOwnedForVerifier(recursion.engine.Proof, &proof, &proof_owned);
    if (capture) |output|
        try core.verifier.verifyWithProofCapture(recursion.engine.Hasher, recursion.engine.MerkleChannel, allocator, try components.gate.verifierSlice(), &channel, &scheme, moved, output)
    else
        try core.verifier.verify(recursion.engine.Hasher, recursion.engine.MerkleChannel, allocator, try components.gate.verifierSlice(), &channel, &scheme, moved);
    return recursion.protocol.transcriptId(channel.digestWords(), channel.n_draws);
}

fn canonical(value: QM31) !void {
    for (value.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus) return error.InvalidCommonFoldVerifierClaims;
}
