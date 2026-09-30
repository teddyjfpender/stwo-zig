//! One node of the recursive tree and the pair reduction that makes it.
//!
//! Ports `crates/stwo_run_and_prove_recursive_tree/src/fold.rs` and the
//! leaf conversions of `leaf_io.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). A reduction builds the
//! multiverifier over two children in value mode, pads it to the canonical
//! target and proves it against the canonical preprocessed circuit:
//!
//! - an internal fold on the `.internal` profile (`Blake2sM31MerkleChannel`),
//!   whose proof is kept in the in-circuit verifier's `CircuitSerialize`
//!   form for the next layer;
//! - the tree's last fold on the `.root` profile (`Blake2sMerkleChannel`),
//!   whose proof becomes the Cairo circuit verifier's felt stream.
//!
//! Rust re-serializes every internal proof and deserializes it at the next
//! layer; here the structured proof is handed over in memory (design §7.2),
//! which the CircuitSerialize codec makes equivalent: a leaf's bytes decode
//! to the same structure `verifier_proof.prepare` builds for an internal node.

const std = @import("std");
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const prove = @import("../prove.zig");
const air = @import("../air.zig");
const verifier_proof = @import("../verifier_proof.zig");
const cairo_verifier_proof = @import("../cairo_verifier_proof.zig");
const canonical_mod = @import("canonical.zig");

const QM31 = core.fields.qm31.QM31;
const builder = circuit.builder;
const finalize = circuit.common.finalize;
const multiverifier = circuit.statements.multiverifier;
const component_table = circuit.air_eval.component_table;
const PackedNode = wire.packed_node.PackedNode;
const CanonicalCircuit = canonical_mod.CanonicalCircuit;

const StageScope = prove.StageScope;

const log = std.log.scoped(.circuit_recursion);

/// `N_RESERVED`: the output digest's words.
pub const n_digest_words = 8;
pub const Digest = [n_digest_words]u32;

pub const Error = error{
    /// `RecursiveTreeError::BadOutputArity`.
    BadOutputArity,
    /// A circuit output is not a packed `u32` (`QM31::unpack_u32`).
    BadOutputValue,
    /// The multiverifier circuit rejects its inputs: a child proof does not
    /// verify (upstream's `debug_assert!(context.is_circuit_valid())`).
    MultiverifierRejectedInputs,
    /// A root entry (felt stream) was handed to another reduction.
    RootProofFolded,
};

/// The folds' storage (design §9.3): every tree, the shared preprocessed
/// tree included, keeps only its committed evaluations. Under the circuit
/// FRI config's blowup 1 those are the composition and quotient domain, so
/// no stage re-extends a column from coefficients; compact storage (large
/// columns as coefficients) would re-extend each one for composition,
/// quotients and decommitment, about a quarter of a reduction, for about
/// the same peak. Never changes the bytes.
pub const default_options: prove.Options = .{ .evaluations_only = true };

/// Everything a reduction reads: built once per tree.
pub const Fold = struct {
    canonical: *const CanonicalCircuit,
    /// The circuit AIR's in-circuit evaluators.
    table: *const component_table.Table,
    /// The circuit AIR's recorded constraint programs (`air.parse`).
    bundle: *const air.Bundle,
    /// Execution choices that never change bytes.
    options: prove.Options = .{},
    /// The backend that proves each reduction; never changes bytes.
    provers: *const prove.Provers = &prove.cpu_provers,
    /// Owns every `PackedNode` of the tree; outlives the fold.
    packed_allocator: std.mem.Allocator,
};

/// A node's proof: a `CircuitSerialize` proof below the root, the Cairo
/// verifier's felt stream at the root.
pub const NodeProof = union(enum) {
    circuit: wire.circuit_serialize.Proof,
    root: wire.circuit_felt_stream.CairoCircuitProof,
};

/// `LayerEntry`: one live node of the tree.
pub const LayerEntry = struct {
    /// Owns the proof's slices.
    arena: std.heap.ArenaAllocator,
    proof: NodeProof,
    /// The node circuit's preprocessed root, as eight little-endian words.
    preprocessed_root: Digest,
    /// The node circuit's output digest (unreduced Blake2s words).
    output_digest: Digest,
    /// The packed-output subtree rooted here (in `Fold.packed_allocator`).
    packed_output: PackedNode,

    pub fn deinit(self: *LayerEntry) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// `LayerEntry::from_leaf`: the leaf's proof decoded with the tree's
    /// proof config, its preprocessed root as declared, its output digest
    /// recomputed from the hashed-output preimage.
    pub fn fromLeaf(gpa: std.mem.Allocator, fold: *const Fold, leaf: wire.leaf_proof_json.LeafInput) !LayerEntry {
        const config = fold.canonical.proofConfig();
        var decoded = try wire.circuit_serialize.deserializeProof(gpa, leaf.proof.proof, config);
        errdefer decoded.deinit();
        // Upstream (`deserialize_proof_with_config` on a slice) ignores
        // bytes after the proof; so does this port.
        if (decoded.consumed != leaf.proof.proof.len)
            log.warn("leaf proof: {d} bytes after the proof ignored", .{leaf.proof.proof.len - decoded.consumed});
        const output_digest = try leaf.outputDigest(gpa);
        return .{
            .arena = decoded.arena,
            .proof = .{ .circuit = decoded.proof },
            .preprocessed_root = leaf.proof.circuit_preprocessed_root.words,
            .output_digest = output_digest,
            .packed_output = try leafPackedNode(fold.packed_allocator, leaf.proof.circuit_hash.words, leaf.output_preimage),
        };
    }
};

/// `PackedNode::leaf`: the leaf circuit's `Composite` over its `Plain`
/// preimage reveal.
pub fn leafPackedNode(allocator: std.mem.Allocator, circuit_hash: Digest, preimage: []const []const u8) std.mem.Allocator.Error!PackedNode {
    const felts = try allocator.alloc([]const u8, preimage.len);
    for (felts, preimage) |*out, felt| out.* = try allocator.dupe(u8, felt);
    const subtasks = try allocator.alloc(PackedNode, 1);
    subtasks[0] = .{ .plain = felts };
    return .{ .composite = .{ .circuit_hash = circuit_hash, .subtasks = subtasks } };
}

/// `reduce_pair`: folds `left` and `right` (consumed) into their parent.
pub fn reducePair(gpa: std.mem.Allocator, fold: *const Fold, left: *LayerEntry, right: *LayerEntry, layer_idx: usize, pair_idx: usize, is_root: bool) !LayerEntry {
    defer left.deinit();
    defer right.deinit();
    const subtasks = try fold.packed_allocator.alloc(PackedNode, 2);
    subtasks[0] = left.packed_output;
    subtasks[1] = right.packed_output;
    return reduce(gpa, fold, .{ left, right }, subtasks, layer_idx, pair_idx, is_root);
}

/// `reduce_root_single`: the single-leaf tree's root folds its leaf with
/// itself; the packed root carries the leaf once.
pub fn reduceRootSingle(gpa: std.mem.Allocator, fold: *const Fold, entry: *LayerEntry) !LayerEntry {
    defer entry.deinit();
    const subtasks = try fold.packed_allocator.alloc(PackedNode, 1);
    subtasks[0] = entry.packed_output;
    return reduce(gpa, fold, .{ entry, entry }, subtasks, 1, 0, true);
}

fn reduce(
    gpa: std.mem.Allocator,
    fold: *const Fold,
    children: [2]*const LayerEntry,
    subtasks: []const PackedNode,
    layer_idx: usize,
    pair_idx: usize,
    is_root: bool,
) !LayerEntry {
    var timer = try std.time.Timer.start();
    const canonical = fold.canonical;
    const recorder = fold.options.recorder;
    var reduce_stage = try StageScope.begin(recorder, if (is_root) "fold_reduce_root" else "fold_reduce_internal", "one reduction");
    defer reduce_stage.end();
    var build_stage = try StageScope.begin(recorder, "fold_build", "build the multiverifier circuit with values");
    defer build_stage.end();

    // The multiverifier circuit over both children, in value mode, padded
    // to the canonical target. Only its value table outlives this block.
    const values = blk: {
        var inputs_arena = std.heap.ArenaAllocator.init(gpa);
        defer inputs_arena.deinit();
        const config = canonical.proofConfig();
        var inputs: [2]multiverifier.MultiverifierInput(QM31) = undefined;
        var proofs: [2]circuit.stark_verifier.proof.Proof(QM31) = undefined;
        for (children, &inputs, &proofs) |child, *input, *child_proof| {
            const decoded = switch (child.proof) {
                .circuit => |*proof| proof,
                // The root is the last reduction; nothing folds it again.
                .root => return error.RootProofFolded,
            };
            child_proof.* = try verifier_proof.circuitVerifierValues(inputs_arena.allocator(), decoded, config);
            input.* = .{
                .proof = child_proof,
                .preprocessed_root = builder.blake.hashValue(QM31, child.preprocessed_root),
                .output_digest = builder.blake.hashValue(QM31, child.output_digest),
            };
        }
        var ctx = try multiverifier.buildMultiverifierCircuit(QM31, gpa, fold.table, &inputs, &canonical.shared, circuit.stark_verifier.verify.NoStages{});
        defer ctx.deinit();
        try finalize.padToTargets(QM31, &ctx, canonical.target_sizes);
        if (!try ctx.isCircuitValid()) return error.MultiverifierRejectedInputs;
        break :blk try gpa.dupe(QM31, ctx.values());
    };
    // The prover frees the value table once the base trace is written.
    var owned_values = OwnedValues{ .gpa = gpa, .values = values };
    defer owned_values.release();
    build_stage.end();
    const build_ns = timer.lap();

    const parent: LayerEntry = if (is_root)
        try proveNode(fold.provers.root, gpa, fold, &owned_values, subtasks, true)
    else
        try proveNode(fold.provers.internal, gpa, fold, &owned_values, subtasks, false);
    log.info("reduce layer {d} pair {d}{s}: build {d} ms, prove {d} ms", .{
        layer_idx,
        pair_idx,
        if (is_root) " (root)" else "",
        build_ns / std.time.ns_per_ms,
        timer.read() / std.time.ns_per_ms,
    });
    return parent;
}

/// A fold's value table, freed by the prover after the base trace
/// (`prove.Options.release_values`) or at the end of the reduction.
const OwnedValues = struct {
    gpa: std.mem.Allocator,
    values: ?[]QM31,

    fn release(self: *OwnedValues) void {
        if (self.values) |values| self.gpa.free(values);
        self.values = null;
    }

    fn releaseErased(context: *anyopaque) void {
        const self: *OwnedValues = @ptrCast(@alignCast(context));
        self.release();
    }
};

fn proveNode(
    proveFn: anytype,
    gpa: std.mem.Allocator,
    fold: *const Fold,
    owned_values: *OwnedValues,
    subtasks: []const PackedNode,
    comptime is_root: bool,
) !LayerEntry {
    const canonical = fold.canonical;
    var options = fold.options;
    options.release_values = .{ .context = owned_values, .release = OwnedValues.releaseErased };
    // Every fold proves the canonical circuit: its committed preprocessed
    // tree and twiddles are shared by all of them (design §7.2).
    var proof = try proveFn(gpa, owned_values.values.?, &canonical.preprocessed, fold.bundle, canonical.shared.pcs_config, canonical.proveOptions(options));
    defer proof.deinit();

    // `extract_root_and_outputs`.
    const root_hash = proof.stark_proof.proof.commitment_scheme_proof.commitments.items[0];
    const preprocessed_root = blake2_hash.digestToU32s(root_hash);
    const circuit_hash_words = blake2_hash.digestToU32s(proof.circuit_hash);
    if (proof.output_values.len != n_digest_words) return error.BadOutputArity;
    var output_digest: Digest = undefined;
    for (&output_digest, proof.output_values) |*word, value| word.* = try unpackU32(value);
    const packed_output: PackedNode = .{ .composite = .{ .circuit_hash = circuit_hash_words, .subtasks = subtasks } };

    if (is_root) {
        const converted = try cairo_verifier_proof.prepare(gpa, &proof);
        return .{
            .arena = converted.arena,
            .proof = .{ .root = converted.proof },
            .preprocessed_root = preprocessed_root,
            .output_digest = output_digest,
            .packed_output = packed_output,
        };
    }
    const converted = try verifier_proof.prepare(gpa, &proof);
    return .{
        .arena = converted.arena,
        .proof = .{ .circuit = converted.proof },
        .preprocessed_root = preprocessed_root,
        .output_digest = output_digest,
        .packed_output = packed_output,
    };
}

/// `QM31::unpack_u32`, failing instead of panicking on a value that is not
/// two `u16` limbs.
fn unpackU32(value: QM31) Error!u32 {
    const limbs = builder.ivalue.limbs(value);
    if (limbs[2] != 0 or limbs[3] != 0 or limbs[0] > 0xffff or limbs[1] > 0xffff) return error.BadOutputValue;
    return limbs[0] | (limbs[1] << 16);
}

test "fold: unpack_u32 reads two u16 limbs and rejects anything else" {
    try std.testing.expectEqual(@as(u32, 0x1234_5678), try unpackU32(QM31.fromU32Unchecked(0x5678, 0x1234, 0, 0)));
    try std.testing.expectError(error.BadOutputValue, unpackU32(QM31.fromU32Unchecked(0x1_0000, 0, 0, 0)));
    try std.testing.expectError(error.BadOutputValue, unpackU32(QM31.fromU32Unchecked(0, 0, 1, 0)));
}

test "fold: a leaf packs as a Composite over its Plain preimage" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var hash: Digest = undefined;
    for (&hash, 0..) |*word, index| word.* = @intCast(30 + index);
    const node = try leafPackedNode(arena.allocator(), hash, &.{ "1", "2" });
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try wire.packed_node.writePackedNode(&out.writer, node);
    try std.testing.expectEqualStrings(
        "{\"Composite\":{\"circuit_hash\":[30,31,32,33,34,35,36,37],\"subtasks\":[{\"Plain\":{\"output_preimage\":[\"1\",\"2\"]}}]}}",
        out.written(),
    );
}
