//! Folding RV64 leaf circuit proofs to one root with the circuit recursion
//! tree, and the native root receiver. A leaf is any circuit proof of the
//! production registry's shared target whose eight outputs are the Blake2s
//! digest of its statement words; the multiverifier binds each child's
//! circuit hash and digest, so the root receiver checks: the root circuit
//! proof, the packed tree's digest recomputation, every leaf's circuit hash
//! against the expected RV64 leaf hash, every leaf digest against its
//! statement words, and the batch chain adjacency over those statements.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const core = @import("stwo_core");
const A = @import("../rv64_authenticated_execution.zig");
const walk = @import("transcript_walk.zig");
pub const admission = @import("root_admission.zig");

const Q = core.fields.qm31.QM31;
const recursion = circuit_cpu.recursion;
const blake2_hash = core.vcs.blake2_hash;

pub const registry_path = "vectors/circuit/official/registries/production.json";

const projection_bytes = @embedFile("circuit_air_projection");
const air_programs_bytes = @embedFile("circuit_air_programs");
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";

/// One serialized RV64 leaf: the circuit proof and what binds it.
pub const LeafFile = struct {
    schema: []const u8 = "rv64-recursion-leaf-v1",
    batch_index: u32,
    circuit_hash: [8]u32,
    /// Diagnostic producer hint only; receiver recomputes and checks trusted pins.
    layout_digest: ?[32]u8 = null,
    preprocessed_root: [8]u32,
    output_digest: [8]u32,
    /// The free transcript words in mix order (the digest preimage).
    statement_words: []const u32,
    /// The receipt's public statement, program omitted (the receiver binds
    /// it to the independent authority as the batch receiver does).
    public: A.Public,
    proof_file: []const u8,
};

/// The circuit AIR assets, authenticated, with the tables the fold needs.
/// Heap-allocated: the evaluator table borrows the projection by pointer.
pub const Assets = struct {
    gpa: std.mem.Allocator,
    projection: circuit.air_eval.projection.Projection,
    table: circuit.air_eval.component_table.Table,
    bundle: circuit_cpu.air.Bundle,
    registry: wire.registry.OwnedRegistry,

    pub fn init(gpa: std.mem.Allocator) !*Assets {
        try authenticate(projection_bytes, projection_sha256);
        try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
        const self = try gpa.create(Assets);
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
        errdefer self.projection.deinit();
        self.table = try circuit.air_eval.circuit_components.build(gpa, &self.projection);
        errdefer self.table.deinit();
        self.bundle = try circuit_cpu.air.parse(gpa, air_programs_bytes);
        errdefer self.bundle.deinit();
        const text = try std.fs.cwd().readFileAlloc(gpa, registry_path, 16 << 20);
        defer gpa.free(text);
        self.registry = try wire.registry.parseRegistry(gpa, text);
        return self;
    }
    pub fn deinit(self: *Assets) void {
        self.registry.deinit();
        self.bundle.deinit();
        self.table.deinit();
        self.projection.deinit();
        const gpa = self.gpa;
        self.* = undefined;
        gpa.destroy(self);
    }
    /// The shared padding target every leaf and fold is padded to.
    pub fn target(self: *const Assets) !circuit.common.finalize.ComponentSizes {
        const entry = try self.registry.registry.multiverifier();
        const config = try self.registry.registry.config(entry.config);
        return circuit.common.finalize.ComponentSizes.fromLogSizes(config.component_log_sizes);
    }
    pub fn circuitFri(self: *const Assets) !core.pcs.config_v2.FriConfigV2 {
        const entry = try self.registry.registry.multiverifier();
        return (try self.registry.registry.config(entry.config)).fri_config;
    }
};

fn authenticate(bytes: []const u8, comptime expected: *const [64]u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected)) return error.EmbeddedAssetDigestMismatch;
}

pub const Root = struct {
    proof_bytes: []u8,
    output_digest: [8]u32,
    preprocessed_root: [8]u32,
    circuit_hash: [8]u32,
    packed_json: []u8,
    n_leaves: usize,
    n_layers: usize,
    n_reductions: usize,
};

/// Folds the leaves (in order) to one internal-profile root proof with up
/// to `jobs` sibling reductions in flight.
pub fn fold(gpa: std.mem.Allocator, assets: *Assets, leaves: []const LeafFile, proofs: []const []const u8, jobs: usize) !Root {
    try admission.validateCount(leaves.len);
    if (proofs.len != leaves.len) return error.LeafCountMismatch;
    var cache = recursion.canonical.Cache.init(gpa, .{ .max_entries = 1, .max_bytes = 64 << 30 });
    defer cache.deinit();
    const canonical = try recursion.canonical.acquire(gpa, &cache, &assets.table, assets.registry.registry, recursion.fold.default_options);
    var packed_arena = std.heap.ArenaAllocator.init(gpa);
    defer packed_arena.deinit();
    const fold_context = recursion.fold.Fold{
        .canonical = canonical,
        .table = &assets.table,
        .bundle = &assets.bundle,
        .options = recursion.fold.default_options,
        .provers = &circuit_cpu.prove.cpu_provers,
        .packed_allocator = packed_arena.allocator(),
    };
    const entries = try gpa.alloc(recursion.fold.LayerEntry, leaves.len);
    defer gpa.free(entries);
    var built: usize = 0;
    errdefer for (entries[0..built]) |*entry| entry.deinit();
    for (leaves, proofs, entries) |leaf, bytes, *entry| {
        var decoded = try wire.circuit_serialize.deserializeProof(gpa, bytes, canonical.proofConfig());
        errdefer decoded.deinit();
        if (decoded.consumed != bytes.len) return error.TrailingLeafProofBytes;
        const preimage = try encodeWords(packed_arena.allocator(), leaf.statement_words);
        entry.* = .{
            .arena = decoded.arena,
            .proof = .{ .circuit = decoded.proof },
            .preprocessed_root = leaf.preprocessed_root,
            .output_digest = leaf.output_digest,
            .packed_output = try recursion.fold.leafPackedNode(packed_arena.allocator(), leaf.circuit_hash, &.{preimage}),
        };
        built += 1;
    }
    var folded = try recursion.tree.foldEntriesBoundedProfile(gpa, &fold_context, entries, jobs, false);
    built = 0;
    defer folded.root.deinit();
    const root_proof = switch (folded.root.proof) {
        .circuit => |*proof| proof,
        .root => return error.UnexpectedRootProfile,
    };
    const proof_bytes = try wire.circuit_serialize.serializeProofAlloc(gpa, root_proof, canonical.proofConfig());
    errdefer gpa.free(proof_bytes);
    var packed_out: std.Io.Writer.Allocating = .init(gpa);
    errdefer packed_out.deinit();
    try wire.packed_node.writePackedNode(&packed_out.writer, folded.root.packed_output);
    return .{
        .proof_bytes = proof_bytes,
        .output_digest = folded.root.output_digest,
        .preprocessed_root = folded.root.preprocessed_root,
        .circuit_hash = blake2_hash.digestToU32s(canonical.circuit_hash),
        .packed_json = try packed_out.toOwnedSlice(),
        .n_leaves = folded.stats.n_leaves,
        .n_layers = folded.stats.n_layers,
        .n_reductions = folded.stats.n_pair_reductions,
    };
}

/// A leaf's revealed statement: its words as fixed-width hex, so the packed
/// tree stays valid JSON text. The digest is Blake2s of the words' LE bytes.
pub fn encodeWords(allocator: std.mem.Allocator, words: []const u32) ![]u8 {
    const out = try allocator.alloc(u8, 8 * words.len);
    for (words, 0..) |word, i| _ = std.fmt.bufPrint(out[8 * i ..][0..8], "{x:0>8}", .{word}) catch unreachable;
    return out;
}

/// One child of a fold as the multiverifier binds it.
pub const Child = struct { circuit_hash: [8]u32, digest: [8]u32 };

/// The multiverifier's output over its children: Blake2s of
/// `circuit_hash || output_digest` per child, in order.
pub fn parentDigest(children: []const Child) [8]u32 {
    var hasher = blake2_hash.Blake2sHasher.init();
    for (children) |child| {
        for (child.circuit_hash) |word| hasher.update(&leBytes(word));
        for (child.digest) |word| hasher.update(&leBytes(word));
    }
    return blake2_hash.digestToU32s(hasher.finalize());
}
fn leBytes(word: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, word, .little);
    return out;
}

pub const RootCheck = struct {
    accepted: bool,
    leaf_hash_checked: usize,
    digest_recomputed: bool,
};

/// Verifies the root circuit proof against the canonical multiverifier
/// shape and recomputes the root digest from the packed tree, requiring
/// leaf `i` to carry the independently trusted topology and expected statement
/// digest in `expected_leaves[i]` (the admitted leaf topology
/// of that batch's layout) and a digest equal to the Blake2s of its
/// revealed statement words.
pub fn verifyRoot(gpa: std.mem.Allocator, assets: *Assets, root: Root, expected_leaves: []const admission.Leaf) !RootCheck {
    try admission.validateCount(expected_leaves.len);
    if (root.n_leaves != expected_leaves.len) return error.LeafCountMismatch;
    var cache = recursion.canonical.Cache.init(gpa, .{ .max_entries = 1, .max_bytes = 64 << 30 });
    defer cache.deinit();
    // The receiver needs only the shape and identity; no preprocessed commit.
    var canonical = try recursion.canonical.CanonicalCircuit.build(gpa, &assets.table, assets.registry.registry);
    defer canonical.deinit(gpa);
    if (!std.mem.eql(u32, &blake2_hash.digestToU32s(canonical.circuit_hash), &root.circuit_hash) or
        !std.mem.eql(u32, &blake2_hash.digestToU32s(canonical.preprocessed_root), &root.preprocessed_root)) return error.RootIdentityMismatch;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const layout = canonical.shared.preprocessed_column_log_sizes;
    const columns = try arena.alloc(wire.verify_request.Column, layout.entries.len);
    for (columns, layout.entries) |*column, source| column.* = .{ .id = source.id, .log_size = source.log_size };
    const request = circuit_cpu.verify.Request{
        .pcs_config = canonical.shared.pcs_config,
        .preprocessed_column_log_sizes = columns,
        .preprocessed_root = root.preprocessed_root,
        .output_digest = root.output_digest,
    };
    const verdict = try circuit_cpu.verify.verifyProofBytes(gpa, &assets.table, &request, root.proof_bytes);
    if (!verdict.isAccepted()) return error.RootProofRejected;
    try verifyPackedStatements(gpa, root.packed_json, expected_leaves, root.circuit_hash, root.output_digest);
    return .{ .accepted = true, .leaf_hash_checked = expected_leaves.len, .digest_recomputed = true };
}

/// Binding check only; the caller must separately verify the physical root.
pub fn verifyPackedStatements(gpa: std.mem.Allocator, json: []const u8, expected_leaves: []const admission.Leaf, expected_fold_hash: [8]u32, expected_digest: [8]u32) !void {
    try admission.validateCount(expected_leaves.len);
    if (json.len > admission.MAX_PACKED_JSON_BYTES) return error.PackedTreeResourceLimit;
    var packed_tree = try wire.packed_node.parsePackedNode(gpa, json);
    defer packed_tree.deinit();
    var leaves: usize = 0;
    var nodes: usize = 0;
    const digest = try recompute(packed_tree.node, expected_leaves, expected_fold_hash, &leaves, &nodes, 0);
    if (leaves != expected_leaves.len) return error.LeafCountMismatch;
    if (!std.mem.eql(u32, &digest, &expected_digest)) return error.RootDigestMismatch;
}

fn recompute(node: wire.packed_node.PackedNode, expected_leaves: []const admission.Leaf, expected_fold_hash: [8]u32, leaves: *usize, nodes: *usize, depth: usize) ![8]u32 {
    if (depth >= admission.MAX_DEPTH or nodes.* >= admission.MAX_NODES) return error.PackedTreeResourceLimit;
    nodes.* += 1;
    switch (node) {
        .plain => return error.PlainNodeAtRoot,
        .composite => |composite| {
            if (composite.subtasks.len == 1 and composite.subtasks[0] == .plain) {
                // A leaf: its circuit hash must be the RV64 leaf's, and its
                // digest is the Blake2s of its revealed statement words.
                if (leaves.* >= expected_leaves.len) return error.LeafCountMismatch;
                const preimage = composite.subtasks[0].plain;
                if (preimage.len != 1 or preimage[0].len % 8 != 0) return error.LeafPreimageShape;
                if (preimage[0].len / 8 > admission.MAX_STATEMENT_WORDS) return error.LeafPreimageShape;
                var hasher = blake2_hash.Blake2sHasher.init();
                var at: usize = 0;
                while (at < preimage[0].len) : (at += 8) {
                    const word = std.fmt.parseInt(u32, preimage[0][at..][0..8], 16) catch return error.LeafPreimageShape;
                    hasher.update(&leBytes(word));
                }
                const digest = blake2_hash.digestToU32s(hasher.finalize());
                try admission.checkLeaf(expected_leaves[leaves.*], composite.circuit_hash, digest);
                leaves.* += 1;
                return digest;
            }
            if (!std.mem.eql(u32, &composite.circuit_hash, &expected_fold_hash)) return error.FoldCircuitHashMismatch;
            if (composite.subtasks.len != 2 and composite.subtasks.len != 1) return error.UnexpectedArity;
            var children: [2]Child = undefined;
            for (composite.subtasks, 0..) |child, i| {
                children[i] = .{ .circuit_hash = switch (child) {
                    .composite => |c| c.circuit_hash,
                    .plain => return error.PlainNodeAtRoot,
                }, .digest = try recompute(child, expected_leaves, expected_fold_hash, leaves, nodes, depth + 1) };
            }
            if (composite.subtasks.len == 1) {
                // A single-leaf tree folds the leaf with itself.
                children[1] = children[0];
            }
            return parentDigest(&children);
        },
    }
}

/// Decodes a leaf's statement words back to the receipt's public values
/// through the same walker: the recorded words must equal the leaf's.
pub fn checkStatementWords(a: std.mem.Allocator, view: A.VerificationView, public: A.Public, words: []const u32) !void {
    var channel = A.P.Channel{};
    var replay = walk.NativeReplay{ .allocator = a, .channel = &channel };
    defer replay.deinit();
    try walk.walkPublic(&replay, view, public);
    if (!std.mem.eql(u32, replay.free.items, words)) return error.LeafStatementWordsMismatch;
}

test {
    _ = @import("root_admission_test.zig");
    _ = @import("native_fixed_root.zig");
}
