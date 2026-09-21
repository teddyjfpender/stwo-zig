//! Owned recursive-verifier inputs from one freshly captured provider proof.
//!
//! The native V2 verifier must publish `VerifiedProofCapture` and all 24
//! relation draws in the same success transaction as its fresh claim. This
//! module cold-reopens the provider verifier program and exact shard plan,
//! checks the capture geometry and commitment roots, snapshots the complete
//! FRI/Merkle witness, and field-hashes every verifier input. SHA-256 values
//! remain native transport custody and never enter the field identity.

const std = @import("std");
const core = @import("stwo_core");

const relations_mod = @import("../air/relation_challenges.zig");
const captured_fri = @import("captured_fri.zig");
const channel = @import("poseidon2_channel.zig");
const emitter = @import("provider_shard_child_field_emitter_v1.zig");
const program_mod = @import("provider_shard_composition_program_v1.zig");
const provider_proof =
    @import("../prover/memory_provider_shards/full_core_provider_proof_v2.zig");
const engine = @import("engine.zig");
const protocol = @import("protocol.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROOF_INPUT_DOMAIN: u32 = 0x5052_4931; // "PRI1"
pub const POSEIDON_RELATION_INDEX: usize = 4;
pub const ProofCapture = core.pcs.verifier.VerifiedProofCapture(engine.Hasher);
pub const PRODUCTION_ACTIVATION = false;

pub const FreshCaptureInputV1 = struct {
    field_input: emitter.FreshVerifierInputV1,
    field_authority: emitter.ChildFieldAuthorityV1,
    capture: *const ProofCapture,
    relation_draws: *const [relations_mod.DRAW_COUNT]QM31,
};

pub const CompositionInputsV1 = struct {
    selector: M31 = M31.one(),
    claimed_sums: [program_mod.CLAIMED_SUM_COUNT]QM31,
    relation_draws: [relations_mod.DRAW_COUNT]QM31,
    composition_randomness: QM31,
    oods_seed: QM31,
};

/// Complete owned FRI/PCS inputs plus the exact row-18 composition values.
/// This is a recursive witness authority, not a verified wrapper receipt.
pub const OwnedV1 = struct {
    allocator: std.mem.Allocator,
    fri: captured_fri.Owned,
    composition: CompositionInputsV1,
    field_authority: emitter.ChildFieldAuthorityV1,
    proof_input_word_count: u32,
    proof_input_authority: channel.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        input: FreshCaptureInputV1,
    ) !OwnedV1 {
        try validateInput(input);
        var fri = try captured_fri.Owned.init(
            allocator,
            .{
                .log_blowup_factor = protocol.FRI_LOG_BLOWUP_FACTOR,
                .log_last_layer_degree_bound = protocol.FRI_LOG_LAST_LAYER_DEGREE_BOUND,
                .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
                .pcs_pow_bits = protocol.PCS_POW_BITS,
                .claimed_sum_count = program_mod.CLAIMED_SUM_COUNT,
            },
            input.capture,
        );
        errdefer fri.deinit();
        const composition = CompositionInputsV1{
            .claimed_sums = .{
                input.field_input.statement.claims.sums[0],
                input.field_input.statement.claims.sums[1],
                input.field_input.statement.ordered_call_claim.terminal,
            },
            .relation_draws = input.relation_draws.*,
            .composition_randomness = input.capture.composition_randomness,
            .oods_seed = input.capture.oods_seed,
        };
        var encoder = Encoder.init(PROOF_INPUT_DOMAIN);
        try encodeProofInputs(&encoder, input, composition);
        const encoded = encoder.finalize();
        const result = OwnedV1{
            .allocator = allocator,
            .fri = fri,
            .composition = composition,
            .field_authority = input.field_authority,
            .proof_input_word_count = encoded.word_count,
            .proof_input_authority = encoded.digest,
        };
        try result.validate();
        return result;
    }

    /// Consumes the transaction-local capture published by the full-core V2
    /// fresh verifier. The proof capture and all 24 relation draws therefore
    /// cross this boundary together; callers cannot substitute a transport
    /// digest for either recursive-verifier input.
    pub fn initFromFreshProviderVerifier(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        field_input: emitter.FreshVerifierInputV1,
        field_authority: emitter.ChildFieldAuthorityV1,
        verified: *const provider_proof.VerifiedProviderCaptureV2(Engine),
    ) !OwnedV1 {
        if (comptime Engine.Hasher == engine.Hasher and
            Engine.MerkleChannel == engine.MerkleChannel and
            Engine.Channel == engine.Channel)
        {
            return init(allocator, .{
                .field_input = field_input,
                .field_authority = field_authority,
                .capture = &verified.proof,
                .relation_draws = &verified.relation_draws,
            });
        } else {
            return error.ProviderRecursiveHashSuiteMismatch;
        }
    }

    pub fn deinit(self: *OwnedV1) void {
        self.fri.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedV1) !void {
        try self.field_authority.validate();
        if (self.proof_input_word_count == 0 or
            self.fri.sampled_values.len != program_mod.SAMPLED_VALUE_COUNT or
            self.fri.claimed_sum_count !=
                @as(u32, program_mod.CLAIMED_SUM_COUNT) or
            self.composition.selector.toU32() != 1)
        {
            return error.InvalidProviderRecursiveVerifierInputs;
        }
        try requireDigest(self.proof_input_authority);
        for (self.composition.claimed_sums) |value| try requireQm31(value);
        for (self.composition.relation_draws) |value| try requireQm31(value);
        try requireQm31(self.composition.composition_randomness);
        try requireQm31(self.composition.oods_seed);
    }
};

fn validateInput(input: FreshCaptureInputV1) !void {
    try input.field_authority.validateAgainst(input.field_input);
    try input.field_input.program.validateAgainst(
        input.field_input.compiler_input,
    );
    const capture = input.capture;
    const geometry = input.field_input.program.geometry;
    if (capture.commitments.len != program_mod.TREE_COUNT or
        capture.column_log_sizes.len != program_mod.TREE_COUNT or
        capture.sampled_points.len != program_mod.TREE_COUNT or
        capture.trace_paths.len != program_mod.TREE_COUNT or
        capture.sampled_values.len != program_mod.SAMPLED_VALUE_COUNT or
        capture.queries.raw.len != protocol.FRI_QUERY_COUNT)
    {
        return error.InvalidProviderRecursiveVerifierInputs;
    }
    const roots = input.field_input.roots;
    const expected_roots = [_]channel.Digest{
        roots.preprocessed_commitment_root,
        roots.main_commitment_root,
        roots.interaction_commitment_root,
        roots.composition_commitment_root,
    };
    for (capture.commitments, expected_roots) |actual, expected| {
        if (!std.meta.eql(actual, expected))
            return error.ProviderRecursiveCommitmentMismatch;
    }
    const trace_log = std.math.add(
        u32,
        geometry.log_size,
        protocol.FRI_LOG_BLOWUP_FACTOR,
    ) catch return error.InvalidProviderRecursiveVerifierInputs;
    const composition_log = std.math.add(
        u32,
        geometry.composition_log_size - geometry.composition_log_split,
        protocol.FRI_LOG_BLOWUP_FACTOR,
    ) catch return error.InvalidProviderRecursiveVerifierInputs;
    try validateTree(
        capture.column_log_sizes[0],
        capture.sampled_points[0],
        program_mod.PREPROCESSED_COLUMN_COUNT,
        trace_log,
        1,
    );
    try validateTree(
        capture.column_log_sizes[1],
        capture.sampled_points[1],
        program_mod.MAIN_COLUMN_COUNT,
        trace_log,
        1,
    );
    try validateTree(
        capture.column_log_sizes[2],
        capture.sampled_points[2],
        program_mod.INTERACTION_COLUMN_COUNT,
        trace_log,
        2,
    );
    try validateTree(
        capture.column_log_sizes[3],
        capture.sampled_points[3],
        program_mod.COMPOSITION_COLUMN_COUNT,
        composition_log,
        1,
    );
    for (input.relation_draws) |value| try requireQm31(value);
    const poseidon_offset = 2 * POSEIDON_RELATION_INDEX;
    if (!input.relation_draws[poseidon_offset].eql(input.field_input.relation.z) or
        !input.relation_draws[poseidon_offset + 1].eql(
            input.field_input.relation.alpha,
        ))
    {
        return error.ProviderRecursiveRelationMismatch;
    }
}

fn validateTree(
    logs: []const u32,
    points: []const []core.circle.CirclePointQM31,
    expected_columns: usize,
    expected_log: u32,
    expected_samples: usize,
) !void {
    if (logs.len != expected_columns or points.len != expected_columns)
        return error.InvalidProviderRecursiveVerifierInputs;
    for (logs, points) |log_size, column_points| {
        if (log_size != expected_log or column_points.len != expected_samples)
            return error.InvalidProviderRecursiveVerifierInputs;
    }
}

fn encodeProofInputs(
    encoder: *Encoder,
    input: FreshCaptureInputV1,
    composition: CompositionInputsV1,
) !void {
    try encoder.word(FORMAT_VERSION);
    try encoder.word(SCHEMA_VERSION);
    try encoder.digest(input.field_authority.verifier_program_authority);
    try encoder.digest(input.field_authority.provider_relation_context);
    try encoder.digest(input.field_authority.provider_claim);
    try encoder.digest(input.field_authority.verified_instance_authority);
    try encoder.count(input.capture.commitments.len);
    for (input.capture.commitments) |root| try encoder.digest(root);
    try encoder.count(input.capture.column_log_sizes.len);
    for (input.capture.column_log_sizes) |logs| {
        try encoder.count(logs.len);
        for (logs) |log_size| try encoder.word(log_size);
    }
    try encoder.count(input.capture.sampled_points.len);
    for (input.capture.sampled_points) |columns| {
        try encoder.count(columns.len);
        for (columns) |points| {
            try encoder.count(points.len);
            for (points) |point| {
                try encoder.qm31(point.x);
                try encoder.qm31(point.y);
            }
        }
    }
    try encoder.qm31Slice(input.capture.sampled_values);
    try encoder.positionSlice(input.capture.queries.raw);
    try encoder.positionSlice(input.capture.queries.unique);
    try encoder.m31Slice(input.capture.queried_values);
    try encoder.qm31Slice(input.capture.deep_answers);
    try encoder.count(input.capture.trace_paths.len);
    for (input.capture.trace_paths) |path| {
        try encoder.word(path.path_depth);
        try encoder.positionSlice(path.positions);
        try encoder.digestSlice(path.siblings);
    }
    try encoder.count(input.capture.fri.layers.len);
    for (input.capture.fri.layers) |layer| {
        try encoder.digest(layer.commitment);
        try encoder.qm31(layer.folding_alpha);
        try encoder.word(layer.fold_step);
        try encoder.word(layer.fold_width);
        try encoder.word(layer.path_depth);
        try encoder.count(layer.query_count);
        try encoder.positionSlice(layer.positions);
        try encoder.qm31Slice(layer.values);
        try encoder.digestSlice(layer.siblings);
    }
    try encoder.qm31Slice(input.capture.last_layer_coefficients);
    try encoder.u64Value(input.capture.proof_of_work);
    try encoder.qm31(input.capture.composition_randomness);
    try encoder.qm31(input.capture.oods_seed);
    try encoder.qm31(input.capture.deep_randomness);
    try encoder.word(composition.selector.toU32());
    for (composition.claimed_sums) |value| try encoder.qm31(value);
    for (composition.relation_draws) |value| try encoder.qm31(value);
}

const EncodedDigest = struct {
    digest: channel.Digest,
    word_count: u32,
};

const Encoder = struct {
    hasher: channel.CanonicalWordHasher,
    word_count: u32 = 0,

    fn init(domain: u32) Encoder {
        return .{ .hasher = channel.CanonicalWordHasher.init(domain) };
    }
    fn word(self: *Encoder, value: anytype) !void {
        const canonical = std.math.cast(u32, value) orelse
            return error.NonCanonicalProviderRecursiveInput;
        if (canonical >= m31.Modulus)
            return error.NonCanonicalProviderRecursiveInput;
        self.hasher.update(&.{M31.fromCanonical(canonical)});
        self.word_count = std.math.add(u32, self.word_count, 1) catch
            return error.ProviderRecursiveInputOverflow;
    }
    fn count(self: *Encoder, value: usize) !void {
        try self.word(std.math.cast(u32, value) orelse
            return error.ProviderRecursiveInputOverflow);
    }
    fn u64Value(self: *Encoder, value: u64) !void {
        var remaining = value;
        for (0..5) |_| {
            try self.word(@as(u32, @intCast(remaining & 0x7fff)));
            remaining >>= 15;
        }
        if (remaining != 0) return error.ProviderRecursiveInputOverflow;
    }
    fn positionSlice(self: *Encoder, values: []const usize) !void {
        try self.count(values.len);
        for (values) |value| try self.u64Value(
            std.math.cast(u64, value) orelse
                return error.ProviderRecursiveInputOverflow,
        );
    }
    fn qm31(self: *Encoder, value: QM31) !void {
        for (value.toM31Array()) |limb| try self.word(limb.toU32());
    }
    fn qm31Slice(self: *Encoder, values: []const QM31) !void {
        try self.count(values.len);
        for (values) |value| try self.qm31(value);
    }
    fn m31Slice(self: *Encoder, values: []const M31) !void {
        try self.count(values.len);
        for (values) |value| try self.word(value.toU32());
    }
    fn digest(self: *Encoder, value: channel.Digest) !void {
        for (value) |limb| try self.word(limb);
    }
    fn digestSlice(self: *Encoder, values: []const channel.Digest) !void {
        try self.count(values.len);
        for (values) |value| try self.digest(value);
    }
    fn finalize(self: *Encoder) EncodedDigest {
        return .{
            .digest = self.hasher.finalize(),
            .word_count = self.word_count,
        };
    }
};

fn requireQm31(value: QM31) !void {
    for (value.toM31Array()) |limb| if (limb.toU32() >= m31.Modulus)
        return error.NonCanonicalProviderRecursiveInput;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidProviderRecursiveVerifierInputs;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidProviderRecursiveVerifierInputs;
}

comptime {
    if (relations_mod.DRAW_COUNT != 24 or POSEIDON_RELATION_INDEX != 4 or
        program_mod.SAMPLED_VALUE_COUNT != 479 or
        program_mod.CLAIMED_SUM_COUNT != 3 or
        protocol.FRI_QUERY_COUNT != 193 or PRODUCTION_ACTIVATION or
        engine.Hasher.Hash != channel.Digest)
    {
        @compileError("provider recursive-verifier input ABI drifted");
    }
}
