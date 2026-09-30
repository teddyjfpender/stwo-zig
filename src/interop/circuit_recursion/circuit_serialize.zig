//! `CircuitSerialize`: the binary wire format of a circuit proof.
//!
//! Port of `crates/circuit_serialize` (`serialize.rs`, `deserialize.rs`) at
//! https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230. The proof's shape and size
//! (`ProofInfo::total_bytes`) are `core.circuit_proof_shape`, the model the
//! in-circuit verifier reads proofs with.
//!
//! The format carries no lengths: every count comes from a `ProofConfig`, so
//! the same bytes decode only under the config they were written with. Field
//! order is that of `CircuitSerialize for Proof<QM31>`:
//!
//! ```text
//! channel_salt QM31 · trace_root · interaction_root · composition_root
//! claimed_sums[n_components] · preprocessed_at_oods[n_pp] · trace_at_oods[n_trace]
//! interaction_at_oods (at_oods, then at_prev for cumulative-sum columns)
//! composition_eval_at_oods[8] · eval_domain_samples (per trace, per column, per query)
//! eval_domain_auth_paths (per tree, per query, per level) · pow_nonce QM31
//! interaction_pow_nonce QM31 · FRI (layer commitments, last-layer coefficients,
//! auth paths per layer/query/level, witnesses per layer/query of 2^step QM31)
//! ```
//!
//! An M31 is its canonical value as 4 little-endian bytes; a QM31 is its four
//! M31 limbs. A Merkle hash is its 32 raw Blake2s bytes: upstream holds it as
//! eight `(low_u16, high_u16, 0, 0)` QM31 words and writes `(high << 16) |
//! low` little-endian, which is the digest's own byte string.
//!
//! As upstream, decoding rejects an M31 at or above P and ignores trailing
//! bytes (`deserializeProof` reports how many it consumed). Encoding checks the
//! proof's shape against the config first, so it never writes a byte string
//! its own decoder would read differently.

const std = @import("std");
const core = @import("stwo_core");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31_modulus = core.fields.m31.Modulus;
const shape = core.circuit_proof_shape;

pub const FriConfig = core.pcs.config_v2.FriConfigV2;

pub const n_traces = shape.n_traces;
pub const n_composition_columns = shape.n_composition_columns;
pub const hash_bytes = shape.hash_bytes;
const m31_bytes = shape.m31_bytes;

/// A Merkle root or authentication-path node: the 32 Blake2s digest bytes.
pub const Hash = [hash_bytes]u8;

pub const DecodeError = error{
    /// `DeserializeError::NotEnoughData`.
    NotEnoughData,
    /// `DeserializeError::ValueOutOfRange`: an M31 limb at or above P.
    ValueOutOfRange,
};

pub const ShapeError = error{
    /// The proof's lengths do not match the config it is encoded under.
    ShapeMismatch,
};

/// The config cannot describe a circuit proof (`ProofShape.validate`).
pub const ConfigError = shape.Error;

/// Trace and interaction column counts of one AIR component.
pub const ComponentShape = shape.ComponentShape;

/// The structure of a circuit proof: `ProofConfig` minus
/// `n_interaction_pow_bits`, which no byte of the format depends on.
pub const ProofConfig = shape.ProofShape;

pub const InteractionAtOods = struct {
    at_oods: QM31,
    /// Present exactly for cumulative-sum columns.
    at_prev: ?QM31,
};

pub const FriProof = struct {
    layer_commitments: []Hash,
    last_layer_coefs: []QM31,
    /// Per layer, query-major: node `level` of query `q` is at
    /// `[q * path_len + level]`, `path_len` the layer's folded domain log size.
    auth_paths: [][]Hash,
    /// Per layer, query-major: coset value `i` of query `q` is at
    /// `[q * 2^step + i]`, `step` the layer's fold step.
    witness: [][]QM31,
};

/// `circuits_stark_verifier::proof::Proof<QM31>` with flat storage.
pub const Proof = struct {
    channel_salt: QM31,
    trace_root: Hash,
    interaction_root: Hash,
    composition_polynomial_root: Hash,
    claimed_sums: []QM31,
    preprocessed_columns_at_oods: []QM31,
    trace_at_oods: []QM31,
    interaction_at_oods: []InteractionAtOods,
    composition_eval_at_oods: [n_composition_columns]QM31,
    /// Per tree, column-major: the sample of column `c` at query `q` is at
    /// `[c * n_queries + q]`.
    eval_domain_samples: [n_traces][]M31,
    /// Per tree, query-major: node `level` of query `q` is at
    /// `[q * logEvaluationDomainSize() + level]`.
    eval_domain_auth_paths: [n_traces][]Hash,
    pow_nonce: QM31,
    interaction_pow_nonce: QM31,
    fri: FriProof,

    /// Checks every length against `config`; `serializeProof` requires it.
    pub fn validateShape(self: *const Proof, config: ProofConfig) (ShapeError || ConfigError)!void {
        try config.validate();
        const n_queries = config.nQueries();
        const columns = config.nColumnsPerTrace();
        try expectLen(self.claimed_sums.len, config.nComponents());
        try expectLen(self.preprocessed_columns_at_oods.len, columns[0]);
        try expectLen(self.trace_at_oods.len, columns[1]);
        try expectLen(self.interaction_at_oods.len, columns[2]);
        for (self.interaction_at_oods, 0..) |value, column| {
            if ((value.at_prev != null) != config.isCumulativeSumColumn(column)) {
                return error.ShapeMismatch;
            }
        }
        for (0..n_traces) |tree| {
            try expectLen(self.eval_domain_samples[tree].len, columns[tree] * n_queries);
            try expectLen(self.eval_domain_auth_paths[tree].len, n_queries * config.logEvaluationDomainSize());
        }
        var steps_buffer: [shape.max_fri_layers]u32 = undefined;
        const steps = config.friFoldSteps(&steps_buffer);
        try expectLen(self.fri.layer_commitments.len, steps.len);
        try expectLen(self.fri.last_layer_coefs.len, @as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound));
        try expectLen(self.fri.auth_paths.len, steps.len);
        try expectLen(self.fri.witness.len, steps.len);
        var path_len = config.logEvaluationDomainSize();
        for (steps, 0..) |step, layer| {
            path_len -= step;
            try expectLen(self.fri.auth_paths[layer].len, n_queries * path_len);
            try expectLen(self.fri.witness[layer].len, n_queries << @intCast(step));
        }
    }
};

fn expectLen(actual: usize, expected: usize) ShapeError!void {
    if (actual != expected) return error.ShapeMismatch;
}

/// A decoded proof and the arena that owns its slices.
pub const DecodedProof = struct {
    arena: std.heap.ArenaAllocator,
    proof: Proof,
    /// Bytes read from the input; anything after them was ignored.
    consumed: usize,

    pub fn deinit(self: *DecodedProof) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// `deserialize_proof_with_config`.
pub fn deserializeProof(
    gpa: std.mem.Allocator,
    bytes: []const u8,
    config: ProofConfig,
) (DecodeError || ConfigError || std.mem.Allocator.Error)!DecodedProof {
    try config.validate();
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    var reader: Reader = .{ .bytes = bytes };

    const n_queries = config.nQueries();
    const columns = config.nColumnsPerTrace();
    var proof: Proof = undefined;
    proof.channel_salt = try reader.qm31();
    proof.trace_root = try reader.hash();
    proof.interaction_root = try reader.hash();
    proof.composition_polynomial_root = try reader.hash();
    proof.claimed_sums = try reader.qm31s(allocator, config.nComponents());
    proof.preprocessed_columns_at_oods = try reader.qm31s(allocator, columns[0]);
    proof.trace_at_oods = try reader.qm31s(allocator, columns[1]);
    proof.interaction_at_oods = try allocator.alloc(InteractionAtOods, columns[2]);
    for (proof.interaction_at_oods, 0..) |*value, column| {
        value.at_oods = try reader.qm31();
        value.at_prev = if (config.isCumulativeSumColumn(column)) try reader.qm31() else null;
    }
    for (&proof.composition_eval_at_oods) |*value| value.* = try reader.qm31();
    for (0..n_traces) |tree| {
        proof.eval_domain_samples[tree] = try reader.m31s(allocator, columns[tree] * n_queries);
    }
    for (0..n_traces) |tree| {
        proof.eval_domain_auth_paths[tree] = try reader.hashes(allocator, n_queries * config.logEvaluationDomainSize());
    }
    proof.pow_nonce = try reader.qm31();
    proof.interaction_pow_nonce = try reader.qm31();

    var steps_buffer: [shape.max_fri_layers]u32 = undefined;
    const steps = config.friFoldSteps(&steps_buffer);
    proof.fri.layer_commitments = try reader.hashes(allocator, steps.len);
    proof.fri.last_layer_coefs = try reader.qm31s(
        allocator,
        @as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound),
    );
    proof.fri.auth_paths = try allocator.alloc([]Hash, steps.len);
    var path_len = config.logEvaluationDomainSize();
    for (proof.fri.auth_paths, steps) |*paths, step| {
        path_len -= step;
        paths.* = try reader.hashes(allocator, n_queries * path_len);
    }
    proof.fri.witness = try allocator.alloc([]QM31, steps.len);
    for (proof.fri.witness, steps) |*witness, step| {
        witness.* = try reader.qm31s(allocator, n_queries << @intCast(step));
    }
    return .{ .arena = arena, .proof = proof, .consumed = reader.position };
}

/// `CircuitSerialize for Proof<QM31>`. Writes exactly
/// `config.serializedLen()` bytes after checking the proof's shape.
pub fn serializeProof(
    writer: *std.Io.Writer,
    proof: *const Proof,
    config: ProofConfig,
) (ShapeError || ConfigError || std.Io.Writer.Error)!void {
    try proof.validateShape(config);
    try writeQm31(writer, proof.channel_salt);
    try writer.writeAll(&proof.trace_root);
    try writer.writeAll(&proof.interaction_root);
    try writer.writeAll(&proof.composition_polynomial_root);
    try writeQm31s(writer, proof.claimed_sums);
    try writeQm31s(writer, proof.preprocessed_columns_at_oods);
    try writeQm31s(writer, proof.trace_at_oods);
    for (proof.interaction_at_oods) |value| {
        try writeQm31(writer, value.at_oods);
        if (value.at_prev) |at_prev| try writeQm31(writer, at_prev);
    }
    try writeQm31s(writer, &proof.composition_eval_at_oods);
    for (proof.eval_domain_samples) |samples| {
        for (samples) |value| try writer.writeInt(u32, value.v, .little);
    }
    for (proof.eval_domain_auth_paths) |paths| try writeHashes(writer, paths);
    try writeQm31(writer, proof.pow_nonce);
    try writeQm31(writer, proof.interaction_pow_nonce);
    try writeHashes(writer, proof.fri.layer_commitments);
    try writeQm31s(writer, proof.fri.last_layer_coefs);
    for (proof.fri.auth_paths) |paths| try writeHashes(writer, paths);
    for (proof.fri.witness) |witness| try writeQm31s(writer, witness);
}

/// Encodes `proof` into a new allocation of exactly `config.serializedLen()`.
pub fn serializeProofAlloc(
    allocator: std.mem.Allocator,
    proof: *const Proof,
    config: ProofConfig,
) (ShapeError || ConfigError || std.mem.Allocator.Error)![]u8 {
    try proof.validateShape(config);
    const bytes = try allocator.alloc(u8, config.serializedLen());
    errdefer allocator.free(bytes);
    var writer = std.Io.Writer.fixed(bytes);
    serializeProof(&writer, proof, config) catch |err| switch (err) {
        // The shape check above sized the buffer exactly.
        error.WriteFailed => unreachable,
        else => |other| return other,
    };
    std.debug.assert(writer.end == bytes.len);
    return bytes;
}

fn writeQm31(writer: *std.Io.Writer, value: QM31) std.Io.Writer.Error!void {
    for (value.toM31Array()) |limb| try writer.writeInt(u32, limb.v, .little);
}

fn writeQm31s(writer: *std.Io.Writer, values: []const QM31) std.Io.Writer.Error!void {
    for (values) |value| try writeQm31(writer, value);
}

fn writeHashes(writer: *std.Io.Writer, values: []const Hash) std.Io.Writer.Error!void {
    for (values) |*value| try writer.writeAll(value);
}

const Reader = struct {
    bytes: []const u8,
    position: usize = 0,

    fn take(self: *Reader, n: usize) DecodeError![]const u8 {
        if (self.bytes.len - self.position < n) return error.NotEnoughData;
        const chunk = self.bytes[self.position..][0..n];
        self.position += n;
        return chunk;
    }

    fn m31(self: *Reader) DecodeError!M31 {
        const value = std.mem.readInt(u32, (try self.take(m31_bytes))[0..m31_bytes], .little);
        if (value >= m31_modulus) return error.ValueOutOfRange;
        return M31.fromCanonical(value);
    }

    fn qm31(self: *Reader) DecodeError!QM31 {
        var limbs: [4]M31 = undefined;
        for (&limbs) |*limb| limb.* = try self.m31();
        return QM31.fromM31Array(limbs);
    }

    fn hash(self: *Reader) DecodeError!Hash {
        return (try self.take(hash_bytes))[0..hash_bytes].*;
    }

    fn m31s(self: *Reader, allocator: std.mem.Allocator, n: usize) (DecodeError || std.mem.Allocator.Error)![]M31 {
        const values = try allocator.alloc(M31, n);
        for (values) |*value| value.* = try self.m31();
        return values;
    }

    fn qm31s(self: *Reader, allocator: std.mem.Allocator, n: usize) (DecodeError || std.mem.Allocator.Error)![]QM31 {
        const values = try allocator.alloc(QM31, n);
        for (values) |*value| value.* = try self.qm31();
        return values;
    }

    fn hashes(self: *Reader, allocator: std.mem.Allocator, n: usize) (DecodeError || std.mem.Allocator.Error)![]Hash {
        const values = try allocator.alloc(Hash, n);
        for (values) |*value| value.* = try self.hash();
        return values;
    }
};

// Test config: two components, a short trace, a blowup and a partial last
// fold, so every section of the format is non-empty and shaped differently.
const test_shapes = [_]ComponentShape{
    .{ .trace_columns = 2, .interaction_columns = 4 },
    .{ .trace_columns = 1, .interaction_columns = 8 },
};
const test_config: ProofConfig = .{
    .n_preprocessed_columns = 3,
    .component_shapes = &test_shapes,
    .log_trace_size = 5,
    .fri = .{ .pow_bits = 10, .log_blowup_factor = 1, .log_last_layer_degree_bound = 1, .n_queries = 2, .fold_step = 3 },
};

fn patternBytes(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, len);
    var state: u32 = 0x9e3779b9;
    for (bytes, 0..) |*byte, index| {
        state = state *% 1664525 +% 1013904223;
        byte.* = @truncate(state >> 24);
        // Keep the top bit of every 4-byte word clear so that any word the
        // format reads as an M31 is below P.
        if (index % 4 == 3) byte.* &= 0x3f;
    }
    return bytes;
}

test "circuit serialize: decode then encode reproduces the bytes" {
    const allocator = std.testing.allocator;
    const bytes = try patternBytes(allocator, test_config.serializedLen());
    defer allocator.free(bytes);
    var decoded = try deserializeProof(allocator, bytes, test_config);
    defer decoded.deinit();
    try std.testing.expectEqual(bytes.len, decoded.consumed);
    const encoded = try serializeProofAlloc(allocator, &decoded.proof, test_config);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded);
}

test "circuit serialize: decoding rejects truncation and out-of-range limbs, ignores trailing bytes" {
    const allocator = std.testing.allocator;
    const len = test_config.serializedLen();
    const bytes = try patternBytes(allocator, len + 5);
    defer allocator.free(bytes);
    try std.testing.expectError(error.NotEnoughData, deserializeProof(allocator, bytes[0 .. len - 1], test_config));

    var trailing = try deserializeProof(allocator, bytes, test_config);
    defer trailing.deinit();
    try std.testing.expectEqual(len, trailing.consumed);

    // The channel salt's first limb, set to P.
    std.mem.writeInt(u32, bytes[0..4], m31_modulus, .little);
    try std.testing.expectError(error.ValueOutOfRange, deserializeProof(allocator, bytes, test_config));
}

test "circuit serialize: encoding rejects a proof whose shape differs from the config" {
    const allocator = std.testing.allocator;
    const bytes = try patternBytes(allocator, test_config.serializedLen());
    defer allocator.free(bytes);
    var decoded = try deserializeProof(allocator, bytes, test_config);
    defer decoded.deinit();

    var proof = decoded.proof;
    proof.interaction_at_oods[4].at_prev = QM31.zero();
    try std.testing.expectError(error.ShapeMismatch, serializeProofAlloc(allocator, &proof, test_config));

    proof = decoded.proof;
    proof.claimed_sums = proof.claimed_sums[0..1];
    try std.testing.expectError(error.ShapeMismatch, serializeProofAlloc(allocator, &proof, test_config));

    var bad_config = test_config;
    bad_config.fri.fold_step = 0;
    try std.testing.expectError(error.InvalidProofShape, deserializeProof(allocator, bytes, bad_config));
}
