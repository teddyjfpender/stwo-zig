//! The root circuit proof as the Cairo circuit verifier's felt252 stream.
//!
//! Port of `crates/circuit_cairo_serialize` (`claim.rs`, `proof.rs`) and of
//! `sort_and_transpose_queried_values` (`crates/cairo-air/src/utils.rs`) at
//! https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, for the one hasher the
//! recursion root uses: `Blake2sMerkleHasher` (the tree's last reduction is
//! proven over `Blake2sMerkleChannel`, `stwo_run_and_prove_recursive_tree`
//! `fold.rs`).
//!
//! Stream layout (`#[derive(CairoSerialize)]` field order):
//!
//! ```text
//! CairoCircuitProof     = claim.output_values Vec<QM31> · interaction_pow u64
//!                         · interaction_claim [QM31; 11] · stark_proof · channel_salt u32
//! CairoStarkProof       = FriConfig · commitments Vec<Hash>
//!                         · sampled_values Vec<Vec<Vec<QM31>>> · decommitments Vec<Vec<Hash>>
//!                         · queried_values Vec<Vec<M31>> · proof_of_work u64 · fri_proof
//! FriProof              = first_layer · inner_layers Vec<FriLayerProof> · last_layer_poly LinePoly
//! FriLayerProof         = fri_witness Vec<QM31> · decommitment Vec<Hash> · commitment Hash
//! ```
//!
//! `queried_values` is already in the verifier's layout: per tree, one
//! vector over all queries (`sortAndTransposeQueriedValues`). The lifting
//! heights of the `PcsConfig` are not on the wire; `CairoCircuitProof::
//! deserialize` takes them from its caller, and so does nothing here: the
//! heights never reach a byte of the stream.

const std = @import("std");
const core = @import("stwo_core");
const cairo_serialize = @import("cairo_serialize.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Hash = cairo_serialize.Blake2sHash;
const FeltReader = cairo_serialize.FeltReader;

pub const FriConfig = cairo_serialize.FriConfig;

/// `circuit_verifier::circuit_components::N_COMPONENTS`: the claimed sums
/// travel as a fixed-size array in `ComponentList` order.
pub const n_circuit_components: usize = 11;
/// Trees of a circuit proof: preprocessed, trace, interaction, composition.
pub const n_trees: usize = 4;

pub const DecodeError = cairo_serialize.DecodeError || error{
    /// Felts left after the proof.
    TrailingData,
} || std.mem.Allocator.Error;

pub const FriLayerProof = struct {
    fri_witness: []QM31,
    /// `MerkleDecommitmentLifted::hash_witness`, the only serialized field.
    decommitment: []Hash,
    commitment: Hash,
};

pub const FriProof = struct {
    first_layer: FriLayerProof,
    inner_layers: []FriLayerProof,
    /// `LinePoly` coefficients; the length is a power of two.
    last_layer_poly: []QM31,
};

pub const CairoStarkProof = struct {
    fri_config: FriConfig,
    commitments: []Hash,
    /// Per tree, per column, the sampled values.
    sampled_values: [][][]QM31,
    /// Per tree, `MerkleDecommitmentLifted::hash_witness`.
    decommitments: [][]Hash,
    /// Per tree, the sorted and transposed queried values.
    queried_values: [][]M31,
    proof_of_work: u64,
    fri_proof: FriProof,
};

/// `CairoCircuitProof<Blake2sMerkleHasher>`.
pub const CairoCircuitProof = struct {
    /// `CairoCircuitClaim::output_values`.
    output_values: []QM31,
    interaction_pow: u64,
    /// `CairoCircuitInteractionClaim::claimed_sums`, in `ComponentList` order.
    claimed_sums: [n_circuit_components]QM31,
    stark_proof: CairoStarkProof,
    channel_salt: u32,
};

/// A decoded proof and the arena that owns its slices.
pub const DecodedProof = struct {
    arena: std.heap.ArenaAllocator,
    proof: CairoCircuitProof,

    pub fn deinit(self: *DecodedProof) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Decodes a whole felt stream. Felts after the proof are an error: upstream
/// `CairoCircuitProof::deserialize` stops at the proof's end, and its round-trip
/// test asserts that nothing follows.
pub fn decode(gpa: std.mem.Allocator, felts: []const u64) DecodeError!DecodedProof {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    var reader: FeltReader = .{ .felts = felts };

    var proof: CairoCircuitProof = undefined;
    proof.output_values = try reader.qm31Vec(allocator);
    proof.interaction_pow = try reader.u64();
    for (&proof.claimed_sums) |*sum| sum.* = try reader.qm31();
    proof.stark_proof = try readStarkProof(&reader, allocator);
    proof.channel_salt = try reader.u32();
    if (reader.remaining() != 0) return error.TrailingData;
    return .{ .arena = arena, .proof = proof };
}

fn readStarkProof(reader: *FeltReader, allocator: std.mem.Allocator) DecodeError!CairoStarkProof {
    var proof: CairoStarkProof = undefined;
    proof.fri_config = try reader.friConfig();
    proof.commitments = try reader.hashVec(allocator);
    proof.sampled_values = try allocator.alloc([][]QM31, try reader.length());
    for (proof.sampled_values) |*tree| {
        tree.* = try allocator.alloc([]QM31, try reader.length());
        for (tree.*) |*column| column.* = try reader.qm31Vec(allocator);
    }
    proof.decommitments = try allocator.alloc([]Hash, try reader.length());
    for (proof.decommitments) |*decommitment| decommitment.* = try reader.hashVec(allocator);
    proof.queried_values = try allocator.alloc([]M31, try reader.length());
    for (proof.queried_values) |*tree| tree.* = try reader.m31Vec(allocator);
    proof.proof_of_work = try reader.u64();
    proof.fri_proof.first_layer = try readFriLayer(reader, allocator);
    proof.fri_proof.inner_layers = try allocator.alloc(FriLayerProof, try reader.length());
    for (proof.fri_proof.inner_layers) |*layer| layer.* = try readFriLayer(reader, allocator);
    proof.fri_proof.last_layer_poly = try reader.linePoly(allocator);
    return proof;
}

fn readFriLayer(reader: *FeltReader, allocator: std.mem.Allocator) DecodeError!FriLayerProof {
    return .{
        .fri_witness = try reader.qm31Vec(allocator),
        .decommitment = try reader.hashVec(allocator),
        .commitment = try reader.blake2sHash(),
    };
}

/// `CairoSerialize for CairoCircuitProof`, into any felt sink (see
/// `cairo_serialize.FeltWriter`).
pub fn encode(sink: anytype, proof: *const CairoCircuitProof) !void {
    var writer: cairo_serialize.FeltWriter(@TypeOf(sink)) = .{ .sink = sink };
    try writer.qm31Vec(proof.output_values);
    try writer.felt(proof.interaction_pow);
    for (proof.claimed_sums) |sum| try writer.qm31(sum);

    const stark = &proof.stark_proof;
    try writer.friConfig(stark.fri_config);
    try writer.hashVec(stark.commitments);
    try writer.felt(stark.sampled_values.len);
    for (stark.sampled_values) |tree| {
        try writer.felt(tree.len);
        for (tree) |column| try writer.qm31Vec(column);
    }
    try writer.felt(stark.decommitments.len);
    for (stark.decommitments) |decommitment| try writer.hashVec(decommitment);
    try writer.felt(stark.queried_values.len);
    for (stark.queried_values) |tree| try writer.m31Vec(tree);
    try writer.felt(stark.proof_of_work);
    try writeFriLayer(&writer, &stark.fri_proof.first_layer);
    try writer.felt(stark.fri_proof.inner_layers.len);
    for (stark.fri_proof.inner_layers) |*layer| try writeFriLayer(&writer, layer);
    try writer.linePoly(stark.fri_proof.last_layer_poly);
    try writer.felt(proof.channel_salt);
}

fn writeFriLayer(writer: anytype, layer: *const FriLayerProof) !void {
    try writer.qm31Vec(layer.fri_witness);
    try writer.hashVec(layer.decommitment);
    try writer.blake2sHash(&layer.commitment);
}

/// Writes `proof` as the root proof file: the pretty felt JSON array
/// `stwo_run_and_prove_recursive_tree` writes to `--proof_path`.
pub fn writeJson(out: *std.Io.Writer, proof: *const CairoCircuitProof) (cairo_serialize.EncodeError || std.Io.Writer.Error)!void {
    var sink = try cairo_serialize.FeltJsonWriter.begin(out);
    try encode(&sink, proof);
    try sink.end();
}

pub const TransposeError = error{
    /// Columns of one tree with different query counts, a log-size list of
    /// the wrong length, or an empty preprocessed tree.
    ShapeMismatch,
} || std.mem.Allocator.Error;

/// `sort_and_transpose_queried_values`: converts tree-major queried values
/// (`queried_values[tree][column][query]`, as the prover stores them) to the
/// layout the Cairo verifier reads: per tree, all columns' values of query 0,
/// then of query 1, and so on. The trace and interaction trees (1 and 2) are
/// first stably sorted by column log size; the preprocessed tree is already
/// sorted and the composition columns share one size, so trees 0 and 3 are
/// only transposed. The query count is taken from the first preprocessed
/// column, as upstream does. The result is owned by `allocator`.
pub fn sortAndTransposeQueriedValues(
    allocator: std.mem.Allocator,
    queried_values: [n_trees][]const []const M31,
    trace_log_sizes: []const u32,
    interaction_log_sizes: []const u32,
) TransposeError![n_trees][]M31 {
    if (queried_values[0].len == 0) return error.ShapeMismatch;
    const n_queries = queried_values[0][0].len;
    const log_sizes = [n_trees]?[]const u32{ null, trace_log_sizes, interaction_log_sizes, null };

    var result: [n_trees][]M31 = undefined;
    var done: usize = 0;
    errdefer for (result[0..done]) |tree| allocator.free(tree);
    for (queried_values, log_sizes, 0..) |columns, sizes, tree| {
        for (columns) |column| if (column.len != n_queries) return error.ShapeMismatch;
        const order = try allocator.alloc(usize, columns.len);
        defer allocator.free(order);
        for (order, 0..) |*slot, index| slot.* = index;
        if (sizes) |column_sizes| {
            if (column_sizes.len != columns.len) return error.ShapeMismatch;
            std.sort.block(usize, order, column_sizes, lessByLogSize);
        }
        const out = try allocator.alloc(M31, columns.len * n_queries);
        for (0..n_queries) |query| {
            for (order, 0..) |column, position| out[query * columns.len + position] = columns[column][query];
        }
        result[tree] = out;
        done += 1;
    }
    return result;
}

fn lessByLogSize(sizes: []const u32, lhs: usize, rhs: usize) bool {
    return sizes[lhs] < sizes[rhs];
}

fn m31s(comptime values: anytype) [values.len]M31 {
    var out: [values.len]M31 = undefined;
    inline for (values, 0..) |value, index| out[index] = M31.fromCanonical(value);
    return out;
}

test "felt stream: sort and transpose follows cairo-air utils" {
    const allocator = std.testing.allocator;
    // Two queries per column.
    const pp = [_][]const M31{ &m31s(.{ 1, 2 }), &m31s(.{ 3, 4 }) };
    const trace = [_][]const M31{ &m31s(.{ 10, 11 }), &m31s(.{ 20, 21 }), &m31s(.{ 30, 31 }) };
    const interaction = [_][]const M31{ &m31s(.{ 40, 41 }), &m31s(.{ 50, 51 }) };
    const composition = [_][]const M31{&m31s(.{ 60, 61 })};
    // Trace sizes 5, 3, 5: the stable sort puts column 1 first and keeps 0
    // before 2. Interaction sizes 4, 4 keep their order.
    const result = try sortAndTransposeQueriedValues(
        allocator,
        .{ &pp, &trace, &interaction, &composition },
        &.{ 5, 3, 5 },
        &.{ 4, 4 },
    );
    defer for (result) |tree| allocator.free(tree);
    const expected = [n_trees][]const M31{
        &m31s(.{ 1, 3, 2, 4 }),
        &m31s(.{ 20, 10, 30, 21, 11, 31 }),
        &m31s(.{ 40, 50, 41, 51 }),
        &m31s(.{ 60, 61 }),
    };
    for (expected, result) |want, got| {
        try std.testing.expectEqual(want.len, got.len);
        for (want, got) |a, b| try std.testing.expectEqual(a.v, b.v);
    }
    try std.testing.expectError(error.ShapeMismatch, sortAndTransposeQueriedValues(
        allocator,
        .{ &pp, &trace, &interaction, &composition },
        &.{ 5, 3 },
        &.{ 4, 4 },
    ));
}

test "felt stream: a hand-built proof encodes, decodes and re-encodes identically" {
    const allocator = std.testing.allocator;
    var hash_a: Hash = undefined;
    for (&hash_a, 0..) |*byte, index| byte.* = @intCast(index * 7);
    const hash_b: Hash = @splat(0xab);
    var witness = [_]QM31{QM31.fromU32Unchecked(1, 2, 3, 4)};
    var decommitment = [_]Hash{hash_a};
    var column = [_]QM31{ QM31.fromU32Unchecked(5, 0, 0, 0), QM31.fromU32Unchecked(6, 0, 0, 0) };
    var tree = [_][]QM31{ &column, &.{} };
    var sampled = [_][][]QM31{&tree};
    var decommitments = [_][]Hash{ &decommitment, &.{} };
    var queried_tree = m31s(.{ 7, 8, 9 });
    var queried = [_][]M31{&queried_tree};
    var commitments = [_]Hash{ hash_a, hash_b };
    var inner = [_]FriLayerProof{.{ .fri_witness = &.{}, .decommitment = &.{}, .commitment = hash_b }};
    var last_layer = [_]QM31{QM31.fromU32Unchecked(9, 9, 9, 9)};
    var outputs = [_]QM31{QM31.fromU32Unchecked(1, 0, 0, 0)};
    var claimed: [n_circuit_components]QM31 = undefined;
    for (&claimed, 0..) |*sum, index| sum.* = QM31.fromU32Unchecked(@intCast(index), 0, 0, 1);

    const proof: CairoCircuitProof = .{
        .output_values = &outputs,
        .interaction_pow = 1 << 40,
        .claimed_sums = claimed,
        .stark_proof = .{
            .fri_config = .{ .pow_bits = 26, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 4 },
            .commitments = &commitments,
            .sampled_values = &sampled,
            .decommitments = &decommitments,
            .queried_values = &queried,
            .proof_of_work = 12345,
            .fri_proof = .{
                .first_layer = .{ .fri_witness = &witness, .decommitment = &decommitment, .commitment = hash_a },
                .inner_layers = &inner,
                .last_layer_poly = &last_layer,
            },
        },
        .channel_salt = 3,
    };

    var felts: std.ArrayList(u64) = .empty;
    defer felts.deinit(allocator);
    try encode(cairo_serialize.FeltList{ .list = &felts, .allocator = allocator }, &proof);
    // Spot-check the head: output vector, interaction PoW, first claimed sum.
    try std.testing.expectEqualSlices(u64, &.{ 1, 1, 0, 0, 0, 1 << 40, 0, 0, 0, 1 }, felts.items[0..10]);
    try std.testing.expectEqual(@as(u64, 3), felts.items[felts.items.len - 1]);

    var decoded = try decode(allocator, felts.items);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u64, 12345), decoded.proof.stark_proof.proof_of_work);
    try std.testing.expectEqual(@as(usize, 2), decoded.proof.stark_proof.sampled_values[0].len);

    var again: std.ArrayList(u64) = .empty;
    defer again.deinit(allocator);
    try encode(cairo_serialize.FeltList{ .list = &again, .allocator = allocator }, &decoded.proof);
    try std.testing.expectEqualSlices(u64, felts.items, again.items);

    try felts.append(allocator, 0);
    try std.testing.expectError(error.TrailingData, decode(allocator, felts.items));
    try std.testing.expectError(error.EndOfStream, decode(allocator, felts.items[0 .. felts.items.len - 2]));
}
