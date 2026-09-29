//! `CircuitSerialize`: the binary wire format of a circuit proof.
//!
//! Port of `crates/circuit_serialize` (`serialize.rs`, `deserialize.rs`) and
//! of the size model `ProofInfo` in `crates/stark_verifier/src/proof.rs`, at
//! https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230.
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

pub const FriConfig = core.pcs.config_v2.FriConfigV2;

/// Trees of a circuit proof: preprocessed, trace, interaction, composition.
pub const n_traces: usize = 4;
/// `N_COMPOSITION_COLUMNS = COMPOSITION_SPLIT (2) * EXTENSION_DEGREE (4)`.
pub const n_composition_columns: usize = 8;
/// The trailing interaction columns of every component that hold the
/// cumulative sum and so are also sampled at the previous point.
pub const n_cumulative_sum_columns_per_component: usize = 4;

pub const hash_bytes: usize = 32;
const m31_bytes: usize = 4;
const qm31_bytes: usize = 4 * m31_bytes;

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

pub const ConfigError = error{
    /// The config cannot describe a circuit proof (see `ProofConfig.validate`).
    InvalidProofConfig,
};

/// Trace and interaction column counts of one AIR component.
pub const ComponentShape = struct {
    trace_columns: usize,
    interaction_columns: usize,
};

/// The structure of a circuit proof: `ProofConfig` minus
/// `n_interaction_pow_bits`, which no byte of the format depends on.
///
/// `component_shapes` is in the order the statement iterates its components
/// (for the circuit AIR, `all_circuit_components`). It is borrowed.
pub const ProofConfig = struct {
    n_preprocessed_columns: usize,
    component_shapes: []const ComponentShape,
    log_trace_size: u32,
    fri: FriConfig,

    /// Rejects a config upstream would assert on or that has no proof shape:
    /// a component with fewer interaction columns than its cumulative sum, a
    /// zero FRI fold step, or a last layer larger than the trace.
    pub fn validate(self: ProofConfig) ConfigError!void {
        for (self.component_shapes) |shape| {
            if (shape.interaction_columns < n_cumulative_sum_columns_per_component) {
                return error.InvalidProofConfig;
            }
        }
        if (self.fri.fold_step == 0) return error.InvalidProofConfig;
        if (self.fri.log_last_layer_degree_bound > self.log_trace_size) {
            return error.InvalidProofConfig;
        }
        if (self.logEvaluationDomainSize() > 31) return error.InvalidProofConfig;
    }

    pub fn nComponents(self: ProofConfig) usize {
        return self.component_shapes.len;
    }

    pub fn nTraceColumns(self: ProofConfig) usize {
        var total: usize = 0;
        for (self.component_shapes) |shape| total += shape.trace_columns;
        return total;
    }

    pub fn nInteractionColumns(self: ProofConfig) usize {
        var total: usize = 0;
        for (self.component_shapes) |shape| total += shape.interaction_columns;
        return total;
    }

    pub fn nCumulativeSumColumns(self: ProofConfig) usize {
        return self.component_shapes.len * n_cumulative_sum_columns_per_component;
    }

    /// `[preprocessed, trace, interaction, composition]` column counts.
    pub fn nColumnsPerTrace(self: ProofConfig) [n_traces]usize {
        return .{
            self.n_preprocessed_columns,
            self.nTraceColumns(),
            self.nInteractionColumns(),
            n_composition_columns,
        };
    }

    pub fn nQueries(self: ProofConfig) usize {
        return self.fri.n_queries;
    }

    pub fn logEvaluationDomainSize(self: ProofConfig) usize {
        return @as(usize, self.log_trace_size) + self.fri.log_blowup_factor;
    }

    /// Number of FRI layers: `compute_all_fold_steps(log_trace_size -
    /// log_last_layer_degree_bound, fold_step).len()`.
    pub fn nFriLayers(self: ProofConfig) usize {
        return std.math.divCeil(usize, self.degreeLogRatio(), self.fri.fold_step) catch unreachable;
    }

    /// The fold step of FRI layer `layer`: `fold_step`, except that the last
    /// layer takes the remainder when the degree ratio is not a multiple.
    pub fn friFoldStep(self: ProofConfig, layer: usize) usize {
        const ratio = self.degreeLogRatio();
        const step: usize = self.fri.fold_step;
        std.debug.assert(layer < self.nFriLayers());
        if (layer + 1 == self.nFriLayers() and ratio % step != 0) return ratio % step;
        return step;
    }

    /// Authentication path length of FRI layer `layer`.
    pub fn friPathLength(self: ProofConfig, layer: usize) usize {
        var path_len = self.logEvaluationDomainSize();
        for (0..layer + 1) |index| path_len -= self.friFoldStep(index);
        return path_len;
    }

    /// Whether interaction column `column` also carries its value at the
    /// previous point: the last four interaction columns of each component.
    pub fn isCumulativeSumColumn(self: ProofConfig, column: usize) bool {
        var start: usize = 0;
        for (self.component_shapes) |shape| {
            const end = start + shape.interaction_columns;
            if (column < end) {
                return column >= end - n_cumulative_sum_columns_per_component;
            }
            start = end;
        }
        unreachable;
    }

    /// `ProofInfo::from_config(config).total_bytes()`: the exact encoded size.
    pub fn serializedLen(self: ProofConfig) usize {
        const columns = self.nColumnsPerTrace();
        const total_columns = columns[0] + columns[1] + columns[2] + columns[3];
        const fixed = (1 + 3 * 2 + 1 + 1) * qm31_bytes;
        const claim = self.nComponents() * qm31_bytes;
        const oods = (total_columns + self.nCumulativeSumColumns()) * qm31_bytes;
        const fri_commitments = self.nFriLayers() * hash_bytes;
        const fri_last_layer = (@as(usize, 1) << @intCast(self.fri.log_last_layer_degree_bound)) * qm31_bytes;

        const eval_samples_per_query = total_columns * m31_bytes;
        const eval_auth_per_query = n_traces * self.logEvaluationDomainSize() * hash_bytes;
        var fri_auth_per_query: usize = 0;
        var fri_witness_per_query: usize = 0;
        for (0..self.nFriLayers()) |layer| {
            fri_auth_per_query += self.friPathLength(layer) * hash_bytes;
            fri_witness_per_query += (@as(usize, 1) << @intCast(self.friFoldStep(layer))) * qm31_bytes;
        }
        const per_query = eval_samples_per_query + eval_auth_per_query + fri_auth_per_query + fri_witness_per_query;
        return fixed + claim + oods + fri_commitments + fri_last_layer + per_query * self.nQueries();
    }

    fn degreeLogRatio(self: ProofConfig) usize {
        return self.log_trace_size - self.fri.log_last_layer_degree_bound;
    }
};

pub const InteractionAtOods = struct {
    at_oods: QM31,
    /// Present exactly for cumulative-sum columns.
    at_prev: ?QM31,
};

pub const FriProof = struct {
    layer_commitments: []Hash,
    last_layer_coefs: []QM31,
    /// Per layer, query-major: node `level` of query `q` is at
    /// `[q * friPathLength(layer) + level]`.
    auth_paths: [][]Hash,
    /// Per layer, query-major: coset value `i` of query `q` is at
    /// `[q * 2^friFoldStep(layer) + i]`.
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
        const n_layers = config.nFriLayers();
        try expectLen(self.fri.layer_commitments.len, n_layers);
        try expectLen(self.fri.last_layer_coefs.len, @as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound));
        try expectLen(self.fri.auth_paths.len, n_layers);
        try expectLen(self.fri.witness.len, n_layers);
        for (0..n_layers) |layer| {
            try expectLen(self.fri.auth_paths[layer].len, n_queries * config.friPathLength(layer));
            try expectLen(self.fri.witness[layer].len, n_queries << @intCast(config.friFoldStep(layer)));
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

    const n_layers = config.nFriLayers();
    proof.fri.layer_commitments = try reader.hashes(allocator, n_layers);
    proof.fri.last_layer_coefs = try reader.qm31s(
        allocator,
        @as(usize, 1) << @intCast(config.fri.log_last_layer_degree_bound),
    );
    proof.fri.auth_paths = try allocator.alloc([]Hash, n_layers);
    for (proof.fri.auth_paths, 0..) |*paths, layer| {
        paths.* = try reader.hashes(allocator, n_queries * config.friPathLength(layer));
    }
    proof.fri.witness = try allocator.alloc([]QM31, n_layers);
    for (proof.fri.witness, 0..) |*witness, layer| {
        witness.* = try reader.qm31s(allocator, n_queries << @intCast(config.friFoldStep(layer)));
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

test "circuit serialize: size model matches the stark_verifier ProofInfo breakdown" {
    // log_trace 5, last layer 1: ratio 4 folds as [3, 1]; eval domain 6.
    try std.testing.expectEqual(@as(usize, 2), test_config.nFriLayers());
    try std.testing.expectEqual(@as(usize, 3), test_config.friFoldStep(0));
    try std.testing.expectEqual(@as(usize, 1), test_config.friFoldStep(1));
    try std.testing.expectEqual(@as(usize, 3), test_config.friPathLength(0));
    try std.testing.expectEqual(@as(usize, 2), test_config.friPathLength(1));
    // Component 0's four interaction columns are all cumulative sum; component
    // 1 has four plain columns (4..7) before its cumulative sum (8..11).
    try std.testing.expect(test_config.isCumulativeSumColumn(0));
    try std.testing.expect(test_config.isCumulativeSumColumn(3));
    try std.testing.expect(!test_config.isCumulativeSumColumn(4));
    try std.testing.expect(!test_config.isCumulativeSumColumn(7));
    try std.testing.expect(test_config.isCumulativeSumColumn(8));
    try std.testing.expect(test_config.isCumulativeSumColumn(11));
    // fixed 144 + claim 32 + oods (26 columns + 8 cumsum) * 16 + fri
    // commitments 64 + last layer 32 + per query (104 + 768 + 160 + 160) * 2.
    try std.testing.expectEqual(@as(usize, 144 + 32 + 544 + 64 + 32 + 1192 * 2), test_config.serializedLen());
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
    try std.testing.expectError(error.InvalidProofConfig, deserializeProof(allocator, bytes, bad_config));
}
