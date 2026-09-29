//! Byte-identical round trips of the upstream circuit-recursion goldens.
//!
//! Every fixture is an upstream file copied verbatim into `vectors/circuit/`
//! (provenance: `vectors/circuit/provenance.json`, checked by
//! `scripts/check_upstream_pins.py`). The tests run from the repository root.
//!
//! Proof configs come from upstream data, not from this package: the
//! per-component column counts from the oracle's `r3/components.json`
//! (`circuit_components` order, which is `all_circuit_components` order), the
//! FRI configs from the registries, and the remaining constants from the
//! upstream sources cited where they are used.

const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");

const circuit_serialize = wire.circuit_serialize;
const cairo_serialize = wire.cairo_serialize;
const felt_stream = wire.circuit_felt_stream;
const leaf_proof_json = wire.leaf_proof_json;
const packed_node = wire.packed_node;
const registry_json = wire.registry;
const json_text = wire.json_text;

const allocator = std.testing.allocator;
const vectors = "vectors/circuit/";
const official = vectors ++ "official/";
const four_leaves = official ++ "recursive_tree/four_leaves/";

/// `CIRCUIT_N_PREPROCESSED_COLUMNS` (`circuit_multiverifier/src/test_utils.rs`):
/// the circuit AIR's preprocessed layout has 45 columns at every size.
const circuit_n_preprocessed_columns: usize = 45;
/// The largest fixed preprocessed column of the circuit AIR is
/// `bitwise_xor_10_*` at log size 20 (`fixed_column_layout`), so a circuit
/// padded to the registry targets has trace log size `max(targets, 20)`
/// (`layout_from_component_sizes`, `CanonicalCircuit::build`).
const circuit_fixed_columns_max_log_size: u32 = 20;

fn readFile(path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, 1 << 26);
}

/// The circuit AIR's 11 component shapes, from the oracle's R3 checkpoint.
fn circuitComponentShapes() ![11]circuit_serialize.ComponentShape {
    const text = try readFile(vectors ++ "r3/components.json");
    defer allocator.free(text);
    var parsed = try json_text.parse(allocator, text);
    defer parsed.deinit();
    const body = try json_text.object(try json_text.field(try json_text.object(parsed.value), "body"));
    const order = try json_text.array(try json_text.field(body, "circuit_components"));
    try std.testing.expectEqual(@as(usize, 11), order.len);
    var shapes: [11]circuit_serialize.ComponentShape = undefined;
    var found: usize = 0;
    for (try json_text.array(try json_text.field(body, "evaluators"))) |item| {
        const evaluator = try json_text.object(item);
        if (!std.mem.eql(u8, try json_text.string(try json_text.field(evaluator, "air")), "circuit")) continue;
        const slot = try json_text.unsigned(usize, try json_text.field(evaluator, "slot"));
        try std.testing.expectEqualStrings(
            try json_text.string(order[slot]),
            try json_text.string(try json_text.field(evaluator, "name")),
        );
        shapes[slot] = .{
            .trace_columns = try json_text.unsigned(usize, try json_text.field(evaluator, "trace_columns")),
            .interaction_columns = try json_text.unsigned(usize, try json_text.field(evaluator, "interaction_columns")),
        };
        found += 1;
    }
    try std.testing.expectEqual(@as(usize, 11), found);
    return shapes;
}

/// The circuit proof config of a registry's circuit proof config.
fn registryProofConfig(
    shapes: []const circuit_serialize.ComponentShape,
    config: registry_json.CircuitProofConfig,
) circuit_serialize.ProofConfig {
    const sizes = config.component_log_sizes;
    const log_trace_size = @max(
        @max(@max(sizes.eq, sizes.qm31_ops), @max(sizes.m31_to_u32, sizes.triple_xor)),
        @max(sizes.blake_g_gate, circuit_fixed_columns_max_log_size),
    );
    return .{
        .n_preprocessed_columns = circuit_n_preprocessed_columns,
        .component_shapes = shapes,
        .log_trace_size = log_trace_size,
        .fri = config.fri_config,
    };
}

fn expectCircuitProofRoundTrip(bytes: []const u8, config: circuit_serialize.ProofConfig) !void {
    try std.testing.expectEqual(bytes.len, config.serializedLen());
    var decoded = try circuit_serialize.deserializeProof(allocator, bytes, config);
    defer decoded.deinit();
    try std.testing.expectEqual(bytes.len, decoded.consumed);
    const encoded = try circuit_serialize.serializeProofAlloc(allocator, &decoded.proof, config);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded);
}

fn loadRegistry(name: []const u8) !registry_json.OwnedRegistry {
    const path = try std.mem.concat(allocator, u8, &.{ official, "registries/", name });
    defer allocator.free(path);
    const text = try readFile(path);
    defer allocator.free(text);
    return registry_json.parseRegistry(allocator, text);
}

test "vectors: the three multiverifier proofs round-trip through CircuitSerialize" {
    const shapes = try circuitComponentShapes();
    // `PCS_CONFIG = get_pcs_config(21, 3)` (`circuit_multiverifier/src/test_utils.rs`,
    // `cairo_verifier/src/privacy.rs`): pow 27, 23 queries, fold step 4.
    const config: circuit_serialize.ProofConfig = .{
        .n_preprocessed_columns = circuit_n_preprocessed_columns,
        .component_shapes = &shapes,
        .log_trace_size = 21,
        .fri = .{ .pow_bits = 27, .log_blowup_factor = 3, .log_last_layer_degree_bound = 0, .n_queries = 23, .fold_step = 4 },
    };
    for ([_][]const u8{ "proof.bin", "proof_cairo.bin", "backward_compatibility_cairo_proof.bin" }) |name| {
        const path = try std.mem.concat(allocator, u8, &.{ official, "circuit_multiverifier/", name });
        defer allocator.free(path);
        const bytes = try readFile(path);
        defer allocator.free(bytes);
        try std.testing.expectEqual(@as(usize, 182_884), bytes.len);
        try expectCircuitProofRoundTrip(bytes, config);
    }
}

test "vectors: registries re-emit byte-identically" {
    for ([_][]const u8{ "leaf_prover_canonical_small.json", "recursive_tree_test.json", "privacy_large_proofs.json" }) |name| {
        const path = try std.mem.concat(allocator, u8, &.{ official, "registries/", name });
        defer allocator.free(path);
        const text = try readFile(path);
        defer allocator.free(text);
        var owned = try registry_json.parseRegistry(allocator, text);
        defer owned.deinit();
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        try registry_json.writeRegistry(&out.writer, owned.registry);
        try std.testing.expectEqualStrings(text, out.written());
        _ = try owned.registry.multiverifier();
        const leaf = owned.registry.leaf_verifiers[0];
        try std.testing.expect((try owned.registry.leafVerifier(leaf.trace_log_size)).circuit_hash.eql(leaf.circuit_hash));
    }
}

test "vectors: the leaf prover's expected output re-emits and its proof round-trips" {
    const text = try readFile(official ++ "leaf_prover/expected_output.json");
    defer allocator.free(text);
    var leaf = try leaf_proof_json.parseSerializedLeafProof(allocator, text);
    defer leaf.deinit();
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try leaf_proof_json.writeSerializedLeafProof(&out.writer, leaf.value);
    try std.testing.expectEqualStrings(text, out.written());

    var registry = try loadRegistry("leaf_prover_canonical_small.json");
    defer registry.deinit();
    const verifier = try registry.registry.leafVerifier(20);
    try std.testing.expect(verifier.circuit_hash.eql(leaf.value.circuit_hash));
    try std.testing.expect(verifier.preprocessed_root.eql(leaf.value.circuit_preprocessed_root));
    const shapes = try circuitComponentShapes();
    try expectCircuitProofRoundTrip(leaf.value.proof, registryProofConfig(&shapes, try registry.registry.config(verifier.config)));
}

test "vectors: four_leaves leaf input, packed tree and root outputs" {
    var registry = try loadRegistry("recursive_tree_test.json");
    defer registry.deinit();
    const multiverifier = try registry.registry.multiverifier();

    const leaf_text = try readFile(four_leaves ++ "leaf.json");
    defer allocator.free(leaf_text);
    var leaf = try leaf_proof_json.parseLeafInput(allocator, leaf_text);
    defer leaf.deinit();
    var leaf_out: std.Io.Writer.Allocating = .init(allocator);
    defer leaf_out.deinit();
    try leaf_proof_json.writeLeafInput(&leaf_out.writer, leaf.value);
    try std.testing.expectEqualStrings(leaf_text, leaf_out.written());

    const shapes = try circuitComponentShapes();
    try expectCircuitProofRoundTrip(
        leaf.value.proof.proof,
        registryProofConfig(&shapes, try registry.registry.config(multiverifier.config)),
    );

    // The tree the fold builds over four copies of this leaf: each leaf is a
    // leaf-circuit node over its preimage, and two multiverifier layers fold them.
    const leaf_hash = leaf.value.proof.circuit_hash.words;
    const leaf_node: packed_node.PackedNode = .{ .composite = .{
        .circuit_hash = leaf_hash,
        .subtasks = &.{.{ .plain = leaf.value.output_preimage }},
    } };
    const inner: packed_node.PackedNode = .{ .composite = .{
        .circuit_hash = multiverifier.circuit_hash.words,
        .subtasks = &.{ leaf_node, leaf_node },
    } };
    const root: packed_node.PackedNode = .{ .composite = .{
        .circuit_hash = multiverifier.circuit_hash.words,
        .subtasks = &.{ inner, inner },
    } };
    const packed_text = try readFile(four_leaves ++ "root_packed.json");
    defer allocator.free(packed_text);
    var packed_out: std.Io.Writer.Allocating = .init(allocator);
    defer packed_out.deinit();
    try packed_node.writePackedNode(&packed_out.writer, root);
    try std.testing.expectEqualStrings(packed_text, packed_out.written());
    var parsed_tree = try packed_node.parsePackedNode(allocator, packed_text);
    defer parsed_tree.deinit();
    var reparsed_out: std.Io.Writer.Allocating = .init(allocator);
    defer reparsed_out.deinit();
    try packed_node.writePackedNode(&reparsed_out.writer, parsed_tree.node);
    try std.testing.expectEqualStrings(packed_text, reparsed_out.written());

    // Root output: each multiverifier outputs blake2s over
    // `circuit_hash_0 ‖ output_0 ‖ circuit_hash_1 ‖ output_1`
    // (`circuit_multiverifier/src/verify.rs`), bottom-up from the leaf digest.
    const leaf_digest = try leaf.value.outputDigest(allocator);
    const inner_digest = foldDigest(leaf_hash, leaf_digest);
    const root_digest = foldDigest(multiverifier.circuit_hash.words, inner_digest);
    const outputs_text = try readFile(four_leaves ++ "root_outputs.json");
    defer allocator.free(outputs_text);
    try std.testing.expectEqual(root_digest, try packed_node.parseRootOutputs(allocator, outputs_text));
    var outputs_out: std.Io.Writer.Allocating = .init(allocator);
    defer outputs_out.deinit();
    try packed_node.writeRootOutputs(&outputs_out.writer, root_digest);
    try std.testing.expectEqualStrings(outputs_text, outputs_out.written());
}

fn foldDigest(circuit_hash: [8]u32, child_output: [8]u32) [8]u32 {
    var hasher = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (0..2) |_| {
        for (circuit_hash ++ child_output) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            hasher.update(&bytes);
        }
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return leaf_proof_json.DigestHex.fromBytes(digest).words;
}

test "vectors: four_leaves root.proof parses and re-emits byte-identically" {
    const text = try readFile(four_leaves ++ "root.proof");
    defer allocator.free(text);
    const felts = try cairo_serialize.parseFeltJson(allocator, text);
    defer allocator.free(felts);
    var decoded = try felt_stream.decode(allocator, felts);
    defer decoded.deinit();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try felt_stream.writeJson(&out.writer, &decoded.proof);
    try std.testing.expectEqualStrings(text, out.written());

    // The decoded structure agrees with the registry and the other root files.
    var registry = try loadRegistry("recursive_tree_test.json");
    defer registry.deinit();
    const multiverifier = try registry.registry.multiverifier();
    const proof_config = try registry.registry.config(multiverifier.config);
    const stark = decoded.proof.stark_proof;
    try std.testing.expectEqual(proof_config.fri_config, stark.fri_config);
    try std.testing.expectEqual(@as(usize, 4), stark.commitments.len);
    try std.testing.expectEqualSlices(u8, &multiverifier.preprocessed_root.toBytes(), &stark.commitments[0]);

    const shapes = try circuitComponentShapes();
    const config = registryProofConfig(&shapes, proof_config);
    const columns = config.nColumnsPerTrace();
    try std.testing.expectEqual(@as(usize, 4), stark.queried_values.len);
    for (stark.queried_values, columns) |tree, n_columns| {
        try std.testing.expectEqual(n_columns * config.nQueries(), tree.len);
    }
    try std.testing.expectEqual(config.nFriLayers() - 1, stark.fri_proof.inner_layers.len);

    const outputs_text = try readFile(four_leaves ++ "root_outputs.json");
    defer allocator.free(outputs_text);
    const outputs = try packed_node.parseRootOutputs(allocator, outputs_text);
    try std.testing.expectEqual(@as(usize, 8), decoded.proof.output_values.len);
    for (decoded.proof.output_values, outputs) |value, word| {
        // `IValue::unpack_u32`: `(low16, high16, 0, 0)`.
        const limbs = value.toM31Array();
        try std.testing.expectEqual(word, limbs[0].v | (limbs[1].v << 16));
        try std.testing.expectEqual(@as(u32, 0), limbs[2].v | limbs[3].v);
    }
}

test "vectors: R0 format checkpoints" {
    const text = try readFile(vectors ++ "r0/primitives.json");
    defer allocator.free(text);
    var parsed = try json_text.parse(allocator, text);
    defer parsed.deinit();
    const body = try json_text.object(try json_text.field(try json_text.object(parsed.value), "body"));
    const formats = try json_text.object(try json_text.field(body, "formats"));

    for (try json_text.array(try json_text.field(formats, "felt252_encoding"))) |item| {
        const case = try json_text.object(item);
        const preimage_items = try json_text.array(try json_text.field(case, "preimage"));
        const preimage = try allocator.alloc([]const u8, preimage_items.len);
        defer allocator.free(preimage);
        var words: std.ArrayList(u32) = .empty;
        defer words.deinit(allocator);
        for (preimage_items, preimage) |felt, *slot| {
            slot.* = try json_text.string(felt);
            try wire.blake2_felt252.appendFeltWords(allocator, &words, try wire.blake2_felt252.parseDecimalFelt(slot.*));
        }
        const expected_words = try json_text.array(try json_text.field(case, "words"));
        try std.testing.expectEqual(expected_words.len, words.items.len);
        for (expected_words, words.items) |want, got| try std.testing.expectEqual(try json_text.unsigned(u32, want), got);
        const digest = try wire.blake2_felt252.outputDigest(allocator, preimage);
        try expectHex(try json_text.string(try json_text.field(case, "output_digest")), &leaf_proof_json.DigestHex.toBytes(.{ .words = digest }));
    }

    for (try json_text.array(try json_text.field(formats, "digest_hex"))) |item| {
        const case = try json_text.object(item);
        var bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, try json_text.string(try json_text.field(case, "bytes")));
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        var writer = json_text.Writer.init(&out.writer, false);
        try leaf_proof_json.DigestHex.fromBytes(bytes).writeJson(&writer);
        try std.testing.expectEqualStrings(try json_text.string(try json_text.field(case, "json")), out.written());
    }

    for (try json_text.array(try json_text.field(formats, "serialized_leaf_proof"))) |item| {
        const case = try json_text.object(item);
        const pretty = try json_text.string(try json_text.field(case, "pretty_json"));
        var leaf = try leaf_proof_json.parseSerializedLeafProof(allocator, pretty);
        defer leaf.deinit();
        try expectHex(try json_text.string(try json_text.field(case, "proof_bytes_hex")), leaf.value.proof);
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        try leaf_proof_json.writeSerializedLeafProof(&out.writer, leaf.value);
        try std.testing.expectEqualStrings(pretty, out.written());
    }
}

fn expectHex(hex: []const u8, bytes: []const u8) !void {
    const expected = try allocator.alloc(u8, hex.len / 2);
    defer allocator.free(expected);
    _ = try std.fmt.hexToBytes(expected, hex);
    try std.testing.expectEqualSlices(u8, expected, bytes);
}
